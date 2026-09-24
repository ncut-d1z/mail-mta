#!/usr/bin/env python3
r"""Minimal self-hosted outbound MTA / alert sender.

This program performs direct SMTP delivery to the recipient domain's MX server.
It deliberately does NOT support SMTP AUTH, account passwords, Gmail/NCUT
credentials, or third-party relay services.

Typical usage on a public server you control:

    python send_test_email.py \
        --helo-hostname mail.example.com \
        --from-address alerts@example.com \
        --to-address user@example.edu \
        --subject "[OK] Job finished" \
        "The job completed successfully."

The machine is expected to have a stable public IP and a DNS identity you
control. Configure forward DNS, reverse DNS (PTR), and SPF before relying on
this program for notifications.
"""

from __future__ import annotations

import argparse
import ipaddress
import smtplib
import socket
import ssl
import sys
import time
from email.message import EmailMessage
from email.policy import SMTP as SMTP_POLICY
from email.utils import formatdate, make_msgid

try:
    import dns.exception
    import dns.resolver
except ModuleNotFoundError as exc:
    print(
        "Missing dependency 'dnspython'. Install with: "
        "python -m pip install -r requirements.txt",
        file=sys.stderr,
    )
    raise SystemExit(2) from exc


DEFAULT_TIMEOUT = 20.0
DEFAULT_RETRY_DELAYS = "300,900,1800"


def log(area: str, message: str) -> None:
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{stamp}] [{area}] {message}", file=sys.stderr, flush=True)


def parse_retry_delays(value: str) -> tuple[float, ...]:
    text = value.strip()
    if not text or text.lower() in {"0", "off", "none"}:
        return ()

    delays: list[float] = []
    for raw in text.split(","):
        try:
            delay = float(raw.strip())
        except ValueError as exc:
            raise argparse.ArgumentTypeError(
                "retry delays must be comma-separated seconds, e.g. 300,900,1800"
            ) from exc
        if delay <= 0:
            raise argparse.ArgumentTypeError("each retry delay must be > 0")
        delays.append(delay)
    return tuple(delays)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Directly deliver one alert email from your own public MTA "
            "to the destination MX without SMTP AUTH."
        )
    )
    parser.add_argument("text", help="plain-text message body")
    parser.add_argument(
        "--helo-hostname",
        required=True,
        help="public FQDN controlled by you, e.g. mail.example.com",
    )
    parser.add_argument(
        "--from-address",
        required=True,
        help="envelope/header sender on a domain controlled by you",
    )
    parser.add_argument(
        "--to-address",
        required=True,
        help="destination mailbox",
    )
    parser.add_argument(
        "--subject",
        default="Server notification",
        help="message subject",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"DNS/SMTP timeout in seconds (default: {DEFAULT_TIMEOUT:g})",
    )
    parser.add_argument(
        "--retry-delays",
        type=parse_retry_delays,
        default=parse_retry_delays(DEFAULT_RETRY_DELAYS),
        help=(
            "retry delays for transient SMTP failures in seconds; "
            f"default: {DEFAULT_RETRY_DELAYS}; use 0 to disable"
        ),
    )
    parser.add_argument(
        "--no-starttls",
        action="store_true",
        help="do not use opportunistic STARTTLS even if advertised",
    )
    parser.add_argument(
        "--allow-private-helo",
        action="store_true",
        help=(
            "allow an EHLO hostname that resolves only to private/non-global IPs; "
            "intended for diagnostics, not normal public-MTA operation"
        ),
    )
    return parser.parse_args()


def split_address(address: str) -> tuple[str, str]:
    local, sep, domain = address.rpartition("@")
    if not sep or not local or not domain:
        raise ValueError(f"invalid email address: {address!r}")
    return local, domain.rstrip(".").lower()


def validate_hostname(hostname: str) -> str:
    host = hostname.strip().rstrip(".").lower()
    if not host:
        raise ValueError("--helo-hostname cannot be empty")
    if "@" in host:
        raise ValueError("--helo-hostname must be a hostname, not an email address")
    if "." not in host:
        raise ValueError("--helo-hostname must be a fully qualified domain name")
    if any(ch.isspace() for ch in host):
        raise ValueError("--helo-hostname cannot contain whitespace")
    return host


def resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.timeout = DEFAULT_TIMEOUT
    r.lifetime = DEFAULT_TIMEOUT
    log("DNS", f"resolver nameservers={r.nameservers}")
    return r


def query_records(
    r: dns.resolver.Resolver,
    name: str,
    rrtype: str,
) -> list[str]:
    log("DNS", f"query {rrtype} {name}")
    try:
        answers = r.resolve(name, rrtype)
    except dns.resolver.NoAnswer:
        log("DNS", f"result {rrtype} {name}: NOANSWER")
        return []
    except dns.resolver.NXDOMAIN:
        log("DNS", f"result {rrtype} {name}: NXDOMAIN")
        return []
    except dns.exception.DNSException as exc:
        log("DNS", f"result {rrtype} {name}: ERROR {exc!r}")
        return []

    values = [answer.to_text() for answer in answers]
    log("DNS", f"result {rrtype} {name}: {values}")
    return values


def preflight_identity(
    r: dns.resolver.Resolver,
    helo_hostname: str,
    from_domain: str,
    allow_private_helo: bool,
) -> None:
    log(
        "IDENTITY",
        f"EHLO={helo_hostname!r}, sender-domain={from_domain!r}",
    )

    ipv4 = query_records(r, helo_hostname, "A")
    ipv6 = query_records(r, helo_hostname, "AAAA")
    addresses = ipv4 + ipv6
    if not addresses:
        raise RuntimeError(
            f"EHLO hostname {helo_hostname!r} has no A/AAAA record"
        )

    global_addresses: list[str] = []
    nonglobal_addresses: list[str] = []
    for text in addresses:
        try:
            addr = ipaddress.ip_address(text)
        except ValueError:
            continue
        if addr.is_global:
            global_addresses.append(text)
        else:
            nonglobal_addresses.append(text)

    log("IDENTITY", f"global A/AAAA={global_addresses}")
    if nonglobal_addresses:
        log("IDENTITY", f"non-global A/AAAA={nonglobal_addresses}")

    if not global_addresses and not allow_private_helo:
        raise RuntimeError(
            "EHLO hostname resolves only to private/non-global addresses. "
            "The public-MTA route requires a public DNS identity. "
            "Use --allow-private-helo only for diagnostics."
        )

    for address in global_addresses:
        log("DNS", f"PTR lookup {address}")
        try:
            ptr_name, aliases, _ = socket.gethostbyaddr(address)
        except OSError as exc:
            log("DNS", f"PTR result {address}: ERROR {exc!r}")
        else:
            log(
                "DNS",
                f"PTR result {address}: hostname={ptr_name!r}, aliases={aliases!r}",
            )

    query_records(r, from_domain, "TXT")
    query_records(r, f"_dmarc.{from_domain}", "TXT")


def resolve_mx(
    r: dns.resolver.Resolver,
    recipient_domain: str,
) -> list[str]:
    log("DNS", f"query MX {recipient_domain}")
    try:
        answers = r.resolve(recipient_domain, "MX")
    except dns.resolver.NoAnswer:
        log(
            "DNS",
            f"result MX {recipient_domain}: NOANSWER; using implicit MX",
        )
        return [recipient_domain]
    except dns.exception.DNSException as exc:
        raise RuntimeError(
            f"MX lookup failed for {recipient_domain}: {exc}"
        ) from exc

    records = sorted(
        (int(answer.preference), str(answer.exchange).rstrip("."))
        for answer in answers
    )
    log("DNS", f"result MX {recipient_domain}: {records}")

    if any(not host for _, host in records):
        raise RuntimeError(
            f"{recipient_domain} publishes Null MX and does not accept email"
        )

    hosts = [host for _, host in records] if records else [recipient_domain]
    for host in hosts:
        query_records(r, host, "A")
        query_records(r, host, "AAAA")
    return hosts


def build_message(
    helo_hostname: str,
    sender: str,
    recipient: str,
    subject: str,
    text: str,
) -> bytes:
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain=helo_hostname)
    msg.set_content(text, subtype="plain", charset="utf-8")
    raw = msg.as_bytes(policy=SMTP_POLICY)
    log("MESSAGE", f"message bytes={len(raw)}")
    log("MESSAGE", raw.decode("utf-8", errors="replace"))
    return raw


def smtp_failure(exc: BaseException) -> tuple[bool, str]:
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        transient = False
        parts: list[str] = []
        for address, (code, message) in exc.recipients.items():
            code = int(code)
            transient = transient or 400 <= code < 500
            message_text = (
                message.decode("utf-8", errors="replace")
                if isinstance(message, bytes)
                else str(message)
            )
            parts.append(f"{address}: {code} {message_text}")
        return transient, "; ".join(parts)

    if isinstance(exc, smtplib.SMTPResponseException):
        code = int(exc.smtp_code)
        message = exc.smtp_error
        message_text = (
            message.decode("utf-8", errors="replace")
            if isinstance(message, bytes)
            else str(message)
        )
        return 400 <= code < 500, f"{code} {message_text}"

    return True, str(exc)


def deliver_once(
    mx_host: str,
    helo_hostname: str,
    sender: str,
    recipient: str,
    raw_message: bytes,
    timeout: float,
    use_starttls: bool,
) -> None:
    log(
        "SMTP",
        f"connect host={mx_host!r} port=25 "
        f"local_hostname={helo_hostname!r} timeout={timeout:g}",
    )

    smtp = smtplib.SMTP(local_hostname=helo_hostname, timeout=timeout)
    smtp.set_debuglevel(2)

    try:
        code, response = smtp.connect(mx_host, 25)
        log(
            "SMTP",
            f"connect code={code}, response={response!r}, "
            f"local={smtp.sock.getsockname() if smtp.sock else None}, "
            f"peer={smtp.sock.getpeername() if smtp.sock else None}",
        )

        code, response = smtp.ehlo()
        log(
            "SMTP",
            f"EHLO code={code}, response={response!r}, "
            f"features={smtp.esmtp_features!r}",
        )
        if not 200 <= code < 300:
            code, response = smtp.helo()
            log("SMTP", f"HELO fallback code={code}, response={response!r}")

        if use_starttls and smtp.has_extn("starttls"):
            log("SMTP", "STARTTLS advertised; negotiating TLS")
            code, response = smtp.starttls(context=ssl.create_default_context())
            log("SMTP", f"STARTTLS code={code}, response={response!r}")
            if smtp.sock is not None and hasattr(smtp.sock, "version"):
                log(
                    "SMTP",
                    f"TLS version={smtp.sock.version()}, cipher={smtp.sock.cipher()}",
                )
            code, response = smtp.ehlo()
            log(
                "SMTP",
                f"post-TLS EHLO code={code}, response={response!r}, "
                f"features={smtp.esmtp_features!r}",
            )

        log(
            "SMTP",
            f"MAIL FROM=<{sender}> RCPT TO=<{recipient}> "
            f"message_bytes={len(raw_message)}",
        )
        refused = smtp.sendmail(sender, [recipient], raw_message)
        log("SMTP", f"sendmail refused={refused!r}")
        if refused:
            raise smtplib.SMTPRecipientsRefused(refused)
    finally:
        try:
            smtp.quit()
        except (OSError, smtplib.SMTPException) as exc:
            log("SMTP", f"QUIT failed: {exc!r}; closing socket")
            smtp.close()


def deliver(
    mx_hosts: list[str],
    helo_hostname: str,
    sender: str,
    recipient: str,
    raw_message: bytes,
    timeout: float,
    retry_delays: tuple[float, ...],
    use_starttls: bool,
) -> str:
    for attempt in range(len(retry_delays) + 1):
        log("DELIVERY", f"attempt {attempt + 1}/{len(retry_delays) + 1}")
        failures: list[str] = []
        saw_transient = False

        for mx_host in mx_hosts:
            try:
                deliver_once(
                    mx_host=mx_host,
                    helo_hostname=helo_hostname,
                    sender=sender,
                    recipient=recipient,
                    raw_message=raw_message,
                    timeout=timeout,
                    use_starttls=use_starttls,
                )
                log("DELIVERY", f"accepted by MX {mx_host}")
                return mx_host
            except (OSError, smtplib.SMTPException, ssl.SSLError) as exc:
                transient, detail = smtp_failure(exc)
                saw_transient = saw_transient or transient
                failures.append(f"{mx_host}: {detail}")
                log(
                    "DELIVERY",
                    f"MX {mx_host} failed transient={transient}: {detail}",
                )

        detail = "; ".join(failures) if failures else "no usable MX host"
        if saw_transient and attempt < len(retry_delays):
            delay = retry_delays[attempt]
            log(
                "RETRY",
                f"transient failure; retrying in {delay:g}s: {detail}",
            )
            time.sleep(delay)
            continue

        raise RuntimeError(f"delivery failed: {detail}")

    raise RuntimeError("delivery failed")


def main() -> int:
    args = parse_args()

    try:
        if args.timeout <= 0:
            raise ValueError("--timeout must be > 0")

        helo_hostname = validate_hostname(args.helo_hostname)
        _, from_domain = split_address(args.from_address)
        _, recipient_domain = split_address(args.to_address)

        r = resolver()
        r.timeout = args.timeout
        r.lifetime = args.timeout

        preflight_identity(
            r=r,
            helo_hostname=helo_hostname,
            from_domain=from_domain,
            allow_private_helo=args.allow_private_helo,
        )

        mx_hosts = resolve_mx(r, recipient_domain)
        log("DELIVERY", f"MX candidates={mx_hosts!r}")

        raw_message = build_message(
            helo_hostname=helo_hostname,
            sender=args.from_address,
            recipient=args.to_address,
            subject=args.subject,
            text=args.text,
        )

        mx_host = deliver(
            mx_hosts=mx_hosts,
            helo_hostname=helo_hostname,
            sender=args.from_address,
            recipient=args.to_address,
            raw_message=raw_message,
            timeout=args.timeout,
            retry_delays=args.retry_delays,
            use_starttls=not args.no_starttls,
        )
    except (OSError, RuntimeError, ValueError, smtplib.SMTPException) as exc:
        log("ERROR", f"{type(exc).__name__}: {exc}")
        return 1

    print(
        f"Mail accepted by {mx_host}: "
        f"{args.from_address} -> {args.to_address}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
