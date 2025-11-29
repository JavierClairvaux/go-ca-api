#!/bin/bash

# Function to pause and wait for user input
function pause(){
   read -p "Press [Enter] to continue..."
}

# Check for jq, which is required for parsing JSON in the demo
if ! command -v jq &> /dev/null
then
    echo "Error: 'jq' is not installed. Please install it to run this demo."
    echo "For example, on Debian/Ubuntu: sudo apt-get install jq"
    exit 1
fi

# --- Introduction ---
echo "This script will demonstrate the features of the Go CA API."
echo "It will create a Root CA, run the API server, and test the endpoints."
pause

# --- Step 1: Script Setup ---
echo "--- Step 1: Creating Root CA and DNS Configuration ---"

echo
echo "First, we'll create the OpenSSL configuration file for the Root CA."
pause
echo "$ cat > root-ca.conf <<EOF
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
EOF"
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
echo "File 'root-ca.conf' created."
echo
pause

echo "Next, we'll generate the Root CA's private key."
pause
echo "$ openssl genrsa -out root-ca-key.pem 4096"
openssl genrsa -out root-ca-key.pem 4096
echo
pause

echo "Now, we'll self-sign the Root CA certificate."
pause
echo "$ openssl req -new -x509 -key root-ca-key.pem -out root-ca-cert.pem -days 3650 -config root-ca.conf"
openssl req -new -x509 -key root-ca-key.pem -out root-ca-cert.pem -days 3650 -config root-ca.conf
echo
pause

echo "Next, we'll create the DNS CSV file for domain validation."
pause
echo "$ cat > dns.csv <<EOF
example.com,192.168.1.100
test.example.com,192.168.1.101
app.example.com,10.0.0.50
EOF"
cat > dns.csv <<EOF
example.com,192.168.1.100
test.example.com,192.168.1.101
app.example.com,10.0.0.50
EOF
echo
pause

# --- Step 2: Installation and Usage ---
echo "--- Step 2: Running the API Server ---"
echo
echo "Downloading Go modules..."
pause
echo "$ go mod download"
go mod download
echo
pause

echo "Starting the server in the background..."
echo "The server will automatically generate an intermediate CA on its first run."
pause
echo "$ go run main.go -cert ./root-ca-cert.pem -key ./root-ca-key.pem -dns-csv ./dns.csv &"
go run main.go -cert ./root-ca-cert.pem -key ./root-ca-key.pem -dns-csv ./dns.csv &
SERVER_PID=$!
echo
echo "Server starting with PID: $SERVER_PID. Waiting a few seconds for it to initialize..."
sleep 5 # Wait for server to start and generate intermediate CA
echo
pause

# --- Step 3: Generate and Verify a Certificate ---
echo "--- Step 3: Generating and Verifying a Certificate ---"
echo
echo "First, we'll create a certificate configuration file for 'example.com'."
pause
echo "$ cat > cert.conf <<'EOF'
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
EOF"
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
echo
pause

echo "Now, we'll send a request to the /generate endpoint to get a new certificate."
pause
echo "$ url -X POST http://localhost:8080/generate \
  -H "Content-Type: application/json" \
  -d "{\"config\": $(jq -Rs . < cert.conf)}" | jq -r '.certificate' > generated-cert.pem"

curl -X POST http://localhost:8080/generate \
  -H "Content-Type: application/json" \
  -d "{\"config\": $(jq -Rs . < cert.conf)}" | jq -r '.certificate' > generated-cert.pem
echo
echo "Certificate saved to 'generated-cert.pem'."
echo
pause

echo "Let's verify the certificate we just created with the /verify endpoint."
pause
echo "$ curl -X POST http://localhost:8080/verify \
  -H "Content-Type: application/json" \
  -d "{\"certificate\": $(jq -Rs . < generated-cert.pem)}" | jq '.'"

curl -X POST http://localhost:8080/verify \
  -H "Content-Type: application/json" \
  -d "{\"certificate\": $(jq -Rs . < generated-cert.pem)}" | jq '.'
echo
pause

# --- Step 4: Encrypt/Decrypt Data ---
echo "--- Step 4: Encrypting and Decrypting Data ---"
echo
echo "Let's encrypt some data using the /encrypt endpoint."
pause
echo "$ curl -X POST http://localhost:8080/encrypt \
  -H "Content-Type: application/json" \
  -d '{"data": "Hello, this is a secret!"}' | jq -r '.encrypted_data' > encrypted.txt"
  
curl -X POST http://localhost:8080/encrypt \
  -H "Content-Type: application/json" \
  -d '{"data": "Hello, this is a secret!"}' | jq -r '.encrypted_data' > encrypted.txt
echo "Encrypted data saved to 'encrypted.txt'. Here is the content:"
cat encrypted.txt
echo
pause

echo "Now, we'll decrypt that data using the /decrypt endpoint."
pause
ENCRYPTED_DATA=$(cat encrypted.txt)
echo "$ curl -X POST http://localhost:8080/decrypt \
  -H "Content-Type: application/json" \
  -d "{\"encrypted_data\": \"$ENCRYPTED_DATA\"}" | jq '.'"

curl -X POST http://localhost:8080/decrypt \
  -H "Content-Type: application/json" \
  -d "{\"encrypted_data\": \"$ENCRYPTED_DATA\"}" | jq '.'
echo
pause

# --- Step 5: Cleanup ---
echo "--- Step 5: Shutting Down and Cleaning Up ---"
echo
echo "Stopping the API server..."
pause
echo "$ kill $SERVER_PID"
kill $SERVER_PID
wait $SERVER_PID 2>/dev/null
echo "Server stopped."
echo
pause

echo "Finally, we will remove all the files and directories created during this demo."
pause
echo "$ rm -f root-ca.conf root-ca-key.pem root-ca-cert.pem dns.csv cert.conf generated-cert.pem encrypted.txt intermediate-ca-cert.pem intermediate-ca-key.pem"
rm -f root-ca.conf root-ca-key.pem root-ca-cert.pem dns.csv cert.conf generated-cert.pem encrypted.txt intermediate-ca-cert.pem intermediate-ca-key.pem
echo "$ rm -rf certificates/"
rm -rf certificates/
echo "Cleanup complete."
echo
pause

echo "Demo finished!"
