# EchoRDS (C Implementation)

**EchoRDS** è un protocollo di comunicazione e un sistema hardware/software per la trasmissione e decodifica di dati sicuri tramite Radio FM utilizzando RDS (Radio Data System) e lo standard di codifica SPB490.

## 🌐 Panoramica

EchoRDS consente di inviare messaggi (ad esempio, payload JSON o testo) tramite RDS a ricevitori remoti. Il messaggio viene codificato su un server, trasmesso in FM utilizzando un trasmettitore compatibile e ricevuto da una radio FM collegata a un Raspberry Pi. Il Raspberry decodifica il messaggio e lo memorizza in un database locale.

## 🔐 Caratteristiche di Sicurezza

- Crittografia a Chiave Pubblica/Privata (RSA)
- Firma e Verifica dei Messaggi
- Timestamp + Nonce per protezione contro attacchi replay
- Formato dati configurabile (JSON / Binario)

## 📦 Componenti

- `gateway`: codifica e trasmette dati via SPB490 + RDS
- `receiver`: ascolta sulla banda FM e decodifica i messaggi
- `spb490`: interfaccia di basso livello per l'hardware RDS
- `database`: memorizza i payload ricevuti e validati (SQLite)
- `utils`: utilità come la generazione delle chiavi RSA

## 🛠️ Requisiti di Sistema

- Compilatore C (GCC o Clang)
- OpenSSL (per crittografia RSA)
- zlib (per compressione)
- SQLite3 (per database)
- libuuid (per generazione UUID)

## 🔧 Compilazione

```bash
# Clona il repository
git clone https://github.com/username/echords.git
cd app

# Compila il progetto
make

# Installa (opzionale)
sudo make install
```

## 🚀 Utilizzo

### Generazione delle Chiavi

```bash
# Genera una coppia di chiavi RSA
./bin/echords_keygen --output-dir keys
```

### Server Gateway

```bash
# Invia un messaggio
./bin/echords_gateway --public-key keys/public_key.pem --message "ALERTA ZONA 5 - MOVIMENTO NEMICO"

# Specifica un dispositivo RDS reale
./bin/echords_gateway --public-key keys/public_key.pem --message "ALERTA" --rds-device /dev/ttyUSB0
```

### Daemon Ricevitore

```bash
# Avvia il ricevitore
./bin/echords_receiver --private-key keys/private_key.pem --db-path messages.db

# Specifica un dispositivo RDS reale
./bin/echords_receiver --private-key keys/private_key.pem --db-path messages.db --rds-device /dev/ttyUSB0
```

## 📝 Formato dei Messaggi

I messaggi sono oggetti JSON con la seguente struttura:

```json
{
  "type": "alert",
  "timestamp": "2025-06-04T12:00:00Z",
  "nonce": "unique-identifier",
  "data": {
    "message": "Contenuto del messaggio"
  }
}
```

## 🔌 Integrazione Hardware

Per l'integrazione con hardware RDS reale, è necessario:

1. Un trasmettitore FM con supporto RDS (per il gateway)
2. Un ricevitore FM con uscita RDS o un RTL-SDR (per il ricevitore)

## ⚖️ Licenza e Brevetto

Questo progetto è rilasciato sotto licenza GNU AGPLv3.

L'uso commerciale del concetto EchoRDS o di prodotti derivati richiede un'autorizzazione esplicita.
Vedi `PATENT.txt` per maggiori dettagli.

## 🤝 Contribuire

Pull request e segnalazioni di problemi sono benvenute.
Incoraggiamo la ricerca aperta e l'uso umanitario.

---

**Contatto:** [tua email o pagina del progetto]  
**Copyright © 2025**
