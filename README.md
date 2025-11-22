# Go CA API - Certificate Authority Service

A Golang API that provides encryption, decryption, and certificate generation services. Built with `github.com/gin-gonic/gin` and uses OpenSSL for cryptographic operations.

## Requirements

- Go 1.23+
- OpenSSL installed and available in PATH
- Root CA certificate file in PEM format
- Root CA private key file in PEM format
- DNS CSV file mapping domain names to IP addresses

## Installation

```bash
go mod download
```

## Script Setup

### Create a Root CA Certificate

First, create a configuration file for the root CA:

```bash
cat > root-ca.conf <<EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
C = US
ST = State
L = City
O = Root CA Organization
OU = Root CA Unit
CN = Root CA

[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF
```

Generate the root CA private key and self-signed certificate:

```bash
# Generate root CA private key (4096-bit RSA)
openssl genrsa -out root-ca-key.pem 4096

# Generate self-signed root CA certificate (valid for 10 years)
openssl req -new -x509 -key root-ca-key.pem -out root-ca-cert.pem -days 3650 -config root-ca.conf
```

## DNS CSV File Setup

Create a CSV file that maps domain names to IP addresses. This is used for validating certificate generation requests.

```bash
cat > dns.csv <<EOF
example.com,192.168.1.100
test.example.com,192.168.1.101
app.example.com,10.0.0.50
EOF
```

### Files Generated



After running these commands, you'll have:

- `root-ca-key.pem` - Root CA private key (keep secure!)

- `root-ca-cert.pem` - Root CA certificate (distribute to users)

- `dns.csv` - File where DNS names are associated with IP addresses



Each line should contain a domain name and its corresponding IP address, separated by a comma.

## Usage

Start the server with the root CA certificate, private key, and DNS CSV file:

```bash
go run main.go -cert ./root-ca-cert.pem -key ./root-ca-key.pem -dns-csv ./dns.csv
```

Or set a custom port:

```bash
PORT=3000 go run main.go -cert ./root-ca-cert.pem -key ./root-ca-key.pem -dns-csv ./dns.csv
```

### Automatic Intermediate CA Generation

On first run, the application will automatically:
1. Generate an intermediate CA certificate signed by the root CA
2. Store it as `intermediate-ca-cert.pem` and `intermediate-ca-key.pem` in the current directory
3. Use the intermediate CA for all certificate signing and encryption operations

The intermediate CA files are persistent and will be reused on subsequent runs. This creates a proper certificate hierarchy:

```
Root CA (self-signed, provided by you)
  └── Intermediate CA (auto-generated, stored locally)
      └── Generated Certificates (created via /generate endpoint)
```

**Benefits:**
- Better security: The root CA private key is only used once to sign the intermediate CA
- Standard PKI practice: Separates root CA from operational signing
- Easier revocation: You can revoke the intermediate CA without affecting the root CA

### Generate and Verify a Certificate

**Step 1:** Create certificate configuration
```bash
cat > cert.conf <<'EOF'
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = California
L = San Francisco
O = My Organization
OU = Engineering
CN = example.com

[v3_req]
basicConstraints = CA:FALSE
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = example.com
DNS.2 = test.example.com
IP.1 = 192.168.1.100
IP.2 = 192.168.1.101
EOF
```

**Step 2:** Generate certificate
```bash
curl -X POST http://localhost:8080/generate \
  -H "Content-Type: application/json" \
  -d "{\"config\": $(jq -Rs . < cert.conf)}" | jq -r '.certificate' > generated-cert.pem
```

Sample response:
```json
{"certificate":"-----BEGIN CERTIFICATE-----\nMIIFHDCCAwSgAwIBAgI.....VQSLdYLqM8XHGCqtuZWOhg==\n-----END CERTIFICATE-----\n",
"private_key":"-----BEGIN PRIVATE KEY-----\nMIIEvwIBADANBsty0fHFQ==\n-----END PRIVATE KEY-----\n"}

```

**Step 5:** Verify the generated certificate
```bash
curl -X POST http://localhost:8080/verify \
  -H "Content-Type: application/json" \
  -d "{\"certificate\": $(jq -Rs . < generated-cert.pem)}" | jq '.'
```

You should see:
```json
{
  "valid": true,
  "message": "Certificate is valid and was signed by the root CA"
}
```

### Encrypt/Decrypt Data

**Step 1:** Encrypt data via API
```bash
curl -X POST http://localhost:8080/encrypt \
  -H "Content-Type: application/json" \
  -d '{"data": "Hello, World!"}' | jq -r '.encrypted_data' > encrypted.txt
```

**Step 2:** Decrypt data via API
```bash
ENCRYPTED_DATA=$(cat encrypted.txt)
curl -X POST http://localhost:8080/decrypt \
  -H "Content-Type: application/json" \
  -d "{\"encrypted_data\": \"$ENCRYPTED_DATA\"}"
```

## API Endpoints

### POST /verify

Verifies that a certificate was signed by the root CA.

**Request:**
```json
{
  "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
}
```

**Response:**
```json
{
  "valid": true,
  "message": "Certificate is valid and was signed by the root CA"
}
```

Or if verification fails:
```json
{
  "valid": false,
  "message": "Certificate verification failed: error:..."
}
```

**Example using curl:**
```bash
# Verify a certificate from a file
curl -X POST http://localhost:8080/verify \
  -H "Content-Type: application/json" \
  -d "{\"certificate\": $(jq -Rs . < generated-cert.pem)}"
```

### POST /encrypt

Encrypts data using the root CA's public certificate.

**Request:**
```json
{
  "data": "plaintext data to encrypt"
}
```

**Response:**
```json
{
  "encrypted_data": "base64-encoded-encrypted-data"
}
```

**Example using curl:**
```bash
curl -X POST http://localhost:8080/encrypt \
  -H "Content-Type: application/json" \
  -d '{
    "data": "Hello, World!"
  }'
```

### POST /decrypt

Decrypts data that was encrypted with the root CA's public certificate.

**Request:**
```json
{
  "encrypted_data": "base64-encoded-encrypted-data"
}
```

**Response:**
```json
{
  "data": "decrypted plaintext data"
}
```

**Example using curl:**
```bash
curl -X POST http://localhost:8080/decrypt \
  -H "Content-Type: application/json" \
  -d '{
    "encrypted_data": "Vx8y2Kj..."
  }'
```

### POST /generate

Generates a new certificate signed by the root CA. The DNS names and IP addresses in the configuration are validated against the DNS CSV file (pseudo DNS challenge).

**Request:**
```json
{
  "config": "certificate configuration in OpenSSL format"
}
```

**Response:**
```json
{
  "certificate": "-----BEGIN CERTIFICATE-----\n...",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\n..."
}
```

**Example using curl:**

First, create a certificate configuration file:

```bash
cat > cert.conf <<'EOF'
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = California
L = San Francisco
O = My Organization
OU = Engineering
CN = example.com

[v3_req]
basicConstraints = CA:FALSE
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = example.com
DNS.2 = test.example.com
IP.1 = 192.168.1.100
IP.2 = 192.168.1.101
EOF
```

Then send the request:

```bash
# Read config file and send to API
curl -X POST http://localhost:8080/generate \
  -H "Content-Type: application/json" \
  -d "{\"config\": $(jq -Rs . < cert.conf)}"
```

**Important Notes:**
- The DNS names and IP addresses in the config file MUST match entries in the dns.csv file
- Each DNS name in the config must have its corresponding IP address also listed
- For example, if you use `DNS.1 = example.com` and `IP.1 = 192.168.1.100`, then your dns.csv must contain the line: `example.com,192.168.1.100`
- This validation acts as a pseudo DNS challenge to ensure only authorized domain/IP pairs can be certified


## How it Works

### Encryption/Decryption
The API uses OpenSSL's `pkeyutl` command for encryption and decryption:
- **Encryption:** `openssl pkeyutl -encrypt -certin -inkey cert.pem -in plaintext.txt -out encrypted.bin`
- **Decryption:** `openssl pkeyutl -decrypt -inkey private-key.pem -in encrypted.bin -out decrypted.txt`

### Certificate Generation
The certificate generation process:
1. Validates DNS/IP pairs against the CSV file (pseudo DNS challenge)
2. Generates a 2048-bit RSA private key
3. Creates a Certificate Signing Request (CSR) using the provided config
4. Signs the CSR with the **intermediate CA certificate** (not the root CA)
5. Encrypts both the certificate and private key using CMS encryption with the intermediate CA certificate
6. Stores the encrypted certificate and private key in the `certificates/` folder
7. Returns both the certificate and private key in plaintext via the API response

### Certificate Verification
The certificate verification process:
1. Accepts a PEM-encoded certificate
2. Uses OpenSSL's `verify` command to check the certificate chain
3. Validates that the certificate was signed by the root CA
4. Returns verification status and detailed message
5. Command used: `openssl verify -CAfile root-ca-cert.pem cert-to-verify.pem`

## Build

```bash
go build -o ca-api
./ca-api -cert /path/to/root-ca-cert.pem -key /path/to/root-ca-key.pem -dns-csv /path/to/dns.csv
```

## Encrypted Certificate Storage

When certificates are generated via the `/generate` endpoint, the API automatically:
- Encrypts both the certificate and private key using OpenSSL CMS encryption
- Stores the encrypted files in the `certificates/` folder with unique filenames:
  - `certificates/cert_<pid>.enc` - Encrypted certificate
  - `certificates/key_<pid>.enc` - Encrypted private key

### Decrypting Stored Certificates

To decrypt the stored certificates and keys, use the **intermediate CA private key** (not the root CA key):

**Decrypt a certificate:**
```bash
openssl cms -decrypt -in certificates/cert_12345.enc -inform DER -inkey intermediate-ca-key.pem -out decrypted-cert.pem
```

**Decrypt a private key:**
```bash
openssl cms -decrypt -in certificates/key_12345.enc -inform DER -inkey intermediate-ca-key.pem -out decrypted-key.pem
```

**Example: Full decryption workflow**
```bash
# Find the latest encrypted files
CERT_FILE=$(ls -t certificates/cert_*.enc | head -1)
KEY_FILE=$(ls -t certificates/key_*.enc | head -1)

# Decrypt both files using the intermediate CA key
openssl cms -decrypt -in "$CERT_FILE" -inform DER -inkey intermediate-ca-key.pem -out decrypted-cert.pem

openssl cms -decrypt -in "$KEY_FILE" -inform DER -inkey intermediate-ca-key.pem -out decrypted-key.pem

# Verify the decrypted certificate
cat decrypted-cert.pem
cat decrypted-key.pem
```

**Security Note:** Only users with access to the intermediate CA private key can decrypt the stored certificates. The intermediate CA key is automatically generated and stored in the application directory.

## Notes

- The certificate provided via `-cert` should be the **root CA certificate**
- An intermediate CA is automatically generated and signed by the root CA on first run
- The intermediate CA (not the root CA) is used for all certificate signing and encryption operations
- The DNS CSV file acts as a whitelist for certificate generation
- DNS-to-IP mappings must match exactly in the CSV for validation to pass
- RSA encryption has size limitations based on key size (typically max 190-245 bytes for 2048-bit keys)
- Generated certificates are valid for 365 days by default
- Encrypted certificates are stored using CMS (Cryptographic Message Syntax) format in DER encoding
- Certificate hierarchy: Root CA → Intermediate CA → Generated Certificates
