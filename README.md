# Quanta CA - Certificate Signing Guide

## Overview
Quanta-CA is the **root certificate authority** for Quanta’s **trusted peer-to-peer network**. It ensures that only verified contributors can sign messages and participate securely.

This guide shows how to **generate a Certificate Signing Request (CSR)** and submit it to **Quanta-CA** for signing.

---

## Step 1: Generate a Key & CSR (Certificate Signing Request)
Each peer must **generate a private key** and a **CSR** to request a signed certificate.

Run the following command:
```bash
openssl genrsa -out my-peer.key 4096
openssl req -new -key my-peer.key -out my-peer.csr -subj "/C=US/ST=QuantumNet/O=Quanta-Peer/CN=my-username"
```

This will create:
- **`my-peer.key`** (Private Key) → **Keep this private!**
- **`my-peer.csr`** (CSR File) → This is **sent to Quanta-CA for signing.**

---

## Step 2: Submit the CSR for Signing
To get a **Quanta-CA signed certificate**, submit your CSR file using our simple API.

### Using cURL (Easiest way):
```bash
curl -F "file=@my-peer.csr" https://quanta-server.example.com/submit-csr
```

Or manually upload the CSR to the Quanta CA portal.

---

## Step 3: Retrieve Your Signed Certificate
Once approved, you will receive a **signed certificate (`my-peer.crt`)** back.

### Download it using the API:
```bash
curl -O https://quanta-server.example.com/certs/my-username.crt
```

### Verify that Quanta-CA signed it:
```bash
openssl verify -CAfile quanta-ca/certs/rootCA.crt my-peer.crt
```

✔ **Use your new certificate in Quanta’s P2P network!**

---

## Step 4: Using Your Signed Certificate
Your signed certificate and key can now be used in **Quanta P2P connections**.

Example:
```bash
quanta-cli --cert my-peer.crt --key my-peer.key connect
```
This ensures **secure, authenticated messaging** within the network. 🚀

---

## Security Notice
- **DO NOT share your private key (`my-peer.key`)!**
- **DO NOT modify the signed certificate (`my-peer.crt`).**
- **Only use `quanta-ca/certs/rootCA.crt` for verification.**

---

## Future Improvements
- ✅ Automate certificate submission & retrieval via **REST API**
- ✅ Build a simple **web UI** for CSR submission
- ✅ Implement **certificate revocation** for compromised keys

---

**🔗 Learn more at:** [GitHub Repo](https://github.com/quanta-network/quanta-ca)

