# mail-mta

A small self-hosted outbound MTA / alert sender for direct SMTP delivery.

This repository is intended for server-status notifications such as:

- a computation failed;
- a scheduled job completed;
- results are ready for verification.

It **does not use SMTP AUTH**, mailbox passwords, application passwords, Gmail
credentials, NCUT credentials, or third-party SMTP relay accounts. The program
connects directly to the recipient domain's MX server on TCP port 25.

## Network model

```text
application / cron / solver
          |
          v
send_test_email.py
          |
          | DNS MX lookup
          | SMTP :25
          | opportunistic STARTTLS
          v
recipient MX
          |
          v
recipient mailbox
```

This is the public-MTA route. The machine running the program should have a
stable public IP and a DNS identity that you control.

## Required DNS identity

Assume your server uses:

```text
EHLO:       mail.example.com
MAIL FROM:  alerts@example.com
Public IP:  203.0.113.10
```

Configure at least:

```text
mail.example.com.   A      203.0.113.10
203.0.113.10        PTR    mail.example.com.
example.com.        TXT    "v=spf1 ip4:203.0.113.10 -all"
```

For production delivery, DKIM and DMARC are also recommended. This program
currently performs direct SMTP delivery and does not implement DKIM signing.

Do not set EHLO to a hostname owned by Google, Microsoft, NCUT, or another
organization unless that hostname actually resolves to your MTA and is under
your control.

## Install

```powershell
python -m pip install -r requirements.txt
```

or on Linux:

```bash
python3 -m pip install -r requirements.txt
```

## Send a test notification

Replace the example domain with a domain and MTA hostname that you control:

```powershell
python .\send_test_email.py `
    --helo-hostname "mail.example.com" `
    --from-address "alerts@example.com" `
    --to-address "recipient@example.edu" `
    --subject "[OK] Job finished" `
    "The job completed successfully."
```

Linux:

```bash
python3 ./send_test_email.py \
    --helo-hostname mail.example.com \
    --from-address alerts@example.com \
    --to-address recipient@example.edu \
    --subject '[ERROR] Job failed' \
    'The job exited with a non-zero status.'
```

No username or password is requested or stored.

## Diagnostics

The script prints detailed diagnostic logs for:

- DNS resolver configuration;
- EHLO A/AAAA records;
- reverse-DNS/PTR lookup;
- sender-domain TXT/SPF and DMARC records;
- recipient MX lookup;
- MX A/AAAA lookup;
- TCP local/peer endpoints;
- SMTP greeting and commands;
- ESMTP capabilities;
- STARTTLS and negotiated TLS version/cipher;
- MAIL FROM / RCPT TO / DATA results;
- 4xx retry decisions and 5xx permanent failures.

Python's `smtplib` protocol debug output is enabled for the outbound SMTP
session.

## Retry behavior

Transient SMTP failures are retried by default after:

```text
300 s, 900 s, 1800 s
```

Disable retries while debugging:

```powershell
python .\send_test_email.py ... --retry-delays 0 "test"
```

## Important deployment checks

Before relying on the sender for alerts, verify:

1. outbound TCP port 25 is permitted by the hosting provider;
2. the EHLO hostname has public A/AAAA records;
3. reverse DNS (PTR) points back to the MTA hostname;
4. SPF authorizes the public sending IP;
5. the sender domain is under your control;
6. the destination server accepts direct Internet SMTP from your IP;
7. DKIM/DMARC are added if the recipient's anti-spam policy requires them.

A private RFC1918 address such as `10.0.0.0/8` is not by itself a valid public
MTA identity. If the program is behind NAT, the public egress IP and its DNS
identity are what matter to the receiving server.
