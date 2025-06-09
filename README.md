# EchoRDS

**EchoRDS** is an open-source communication protocol and hardware/software system
for broadcasting and decoding secure data via FM Radio using RDS (Radio Data System)
and the SPB490 encoding standard.

## 🌐 Overview

EchoRDS allows you to send messages (e.g., JSON or text payloads) via RDS to remote receivers.
The message is encoded on a server, transmitted over FM using a compatible transmitter,
and received by an FM radio connected to a Raspberry Pi. The Raspberry decodes the message
and stores it in a local database.

## 🔐 Security Features

- Public/Private Key Encryption
- Message Signing and Verification
- Timestamp + Nonce for replay attack protection
- Configurable data format (JSON / Binary)

## 📦 Components

- `gateway-server`: encodes and transmits data via SPB490 + RDS
- `receiver-daemon`: listens on FM band and decodes messages
- `rds-driver`: low-level interface to RDS-capable hardware
- `database`: stores received and validated payloads (e.g., SQLite or PostgreSQL)

## ⚖️ License and Patent

This project is licensed under the GNU AGPLv3.

Commercial use of the EchoRDS concept or derived products requires explicit permission.
See `PATENT.txt` for more details.

## 🤝 Contributing

Pull requests and issue reports are welcome.
We encourage open research and humanitarian use.

---

**Contact:** [your email or project page]  
**Copyright © [year]**
