# Go CA API - Company Decryption Service

A Golang API for the company side that decrypts data encrypted with the company's public certificate. Built with `github.com/gin-gonic/gin` and uses `openssl pkeyutl` for RSA decryption.

## Requirements

- Go 1.23+
- OpenSSL installed and available in PATH
- Company certificate file in PEM format
- Company private key file in PEM format

## Installation

```bash
go mod download
```

## Certificate Setup

### Step 1: Create a Root CA Certificate

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

### Step 2: Create a Company Certificate

Create a configuration file for the company certificate:

```bash
cat > company.conf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = State
L = City
O = Company Organization
OU = Company Unit
CN = Company Name

[v3_req]
basicConstraints = CA:FALSE
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = company.example.com
DNS.2 = www.company.example.com
EOF
```

Generate the company private key and certificate signing request (CSR):

```bash
# Generate company private key (2048-bit RSA)
openssl genrsa -out company-key.pem 2048

# Generate certificate signing request (CSR)
openssl req -new -key company-key.pem -out company.csr -config company.conf
```

### Step 3: Sign the Company Certificate with Root CA

Create an extensions file for signing:

```bash
cat > company-ext.conf <<EOF
basicConstraints = CA:FALSE
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = DNS:company.example.com,DNS:www.company.example.com
EOF
```

Sign the company CSR with the root CA:

```bash
# Sign the company certificate with root CA (valid for 1 year)
openssl x509 -req -in company.csr -CA root-ca-cert.pem -CAkey root-ca-key.pem \
  -CAcreateserial -out company-cert.pem -days 365 -extfile company-ext.conf
```

### Step 4: Verify the Certificate Chain

Verify that the company certificate is properly signed by the root CA:

```bash
# Verify company certificate against root CA
openssl verify -CAfile root-ca-cert.pem company-cert.pem
```

You should see: `company-cert.pem: OK`

### Files Generated

After running these commands, you'll have:
- `root-ca-key.pem` - Root CA private key (keep secure!)
- `root-ca-cert.pem` - Root CA certificate (distribute to users)
- `company-key.pem` - Company private key (keep secure, used by this API)
- `company-cert.pem` - Company certificate (distribute to users for encryption)
- `company.csr` - Certificate signing request (can be deleted after signing)

## Usage

Start the server with the company certificate and private key:

```bash
go run main.go -cert /path/to/company-cert.pem -key /path/to/company-key.pem
```

Or set a custom port:

```bash
PORT=3000 go run main.go -cert /path/to/company-cert.pem -key /path/to/company-key.pem
```

## API Endpoints

### POST /decrypt

Decrypts data that was encrypted with the company's public certificate.

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

## Complete Workflow

### User Side (Encryption)
Users encrypt data with the company's public certificate using OpenSSL directly:

```bash
# Encrypt data with company's certificate
echo "Hello, World!" | openssl pkeyutl -encrypt -certin -inkey company-cert.pem -out encrypted.bin

# Convert to base64 for API transmission (without newlines)
base64 -w 0 encrypted.bin
```

### Company Side (Decryption)
The company runs this API service and receives encrypted data:

```bash
# Company starts the decryption API
go run main.go -cert company-cert.pem -key company-key.pem

# User sends encrypted data to decrypt
# Base64 encode the encrypted file and capture it (without newlines)
ENCRYPTED_DATA=$(base64 -w 0 encrypted.bin)

# Send to decrypt API
curl -X POST http://localhost:8080/decrypt -H "Content-Type: application/json" -d "{\"encrypted_data\": \"$ENCRYPTED_DATA\"}"
```

## How it works

The API uses `openssl pkeyutl -decrypt` to decrypt data with the company's private key. Data must be encrypted with the matching public key from the company certificate.

**Equivalent OpenSSL command:**
```bash
openssl pkeyutl -decrypt -inkey company-key.pem -in encrypted.bin -out decrypted.txt
```

## Build

```bash
go build -o ca-api
./ca-api -cert /path/to/company-cert.pem -key /path/to/company-key.pem
```

## Notes

- The certificate provided via `-cert` should be the **company's certificate** (not the root CA certificate)
- The company certificate can be signed by a root CA for trust verification by users
- Users can verify the company certificate against the root CA before encrypting data
- RSA encryption has size limitations based on key size (typically max 190-245 bytes for 2048-bit keys)
