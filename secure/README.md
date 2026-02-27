# Create Your Own TLS Certificates (OpenSSL)

This folder can store local TLS certificates for development.

## 1. Generate a private key

```bash
openssl genrsa -out server.key 2048
```

## 2. Generate a self-signed certificate

```bash
openssl req -new -x509 -key server.key -out server.crt -days 365 \
  -subj "/C=US/ST=Local/L=Local/O=Elestial/OU=Dev/CN=localhost"
```

This creates:
- `server.key` (private key)
- `server.crt` (certificate)

## 3. (Recommended) Add Subject Alternative Names (SAN)

Modern clients validate SAN, not only `CN`.

Create `san.cnf`:

```ini
[req]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[dn]
C = US
ST = Local
L = Local
O = Elestial
OU = Dev
CN = localhost

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
```

Generate key + cert using SAN config:

```bash
openssl req -new -nodes -x509 -days 365 \
  -keyout server.key -out server.crt \
  -config san.cnf -extensions req_ext
```

## 4. Verify certificate

```bash
openssl x509 -in server.crt -text -noout
```

## 5. Use in app config

Point your server configuration to:
- cert file: `secure/server.crt`
- key file: `secure/server.key`

Do not commit private keys for production environments.
