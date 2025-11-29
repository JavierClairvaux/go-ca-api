package main

import (
	"encoding/base64"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
)

var (
	certPath              string
	privateKeyPath        string
	dnsCSVPath            string
	dnsToIP               map[string]string // Maps DNS names to their allowed IP addresses
	intermediateCertPath  string            // Path to intermediate CA certificate
	intermediateKeyPath   string            // Path to intermediate CA private key
)

// EncryptRequest represents the JSON request body for encryption
type EncryptRequest struct {
	Data string `json:"data" binding:"required"`
}

// EncryptResponse represents the JSON response for encryption
type EncryptResponse struct {
	EncryptedData string `json:"encrypted_data"`
}

// DecryptRequest represents the JSON request body for decryption
type DecryptRequest struct {
	EncryptedData string `json:"encrypted_data" binding:"required"`
}

// DecryptResponse represents the JSON response for decryption
type DecryptResponse struct {
	Data string `json:"data"`
}

// GenerateRequest represents the JSON request body for certificate generation
type GenerateRequest struct {
	Config string `json:"config" binding:"required"`
}

// GenerateResponse represents the JSON response for certificate generation
type GenerateResponse struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
}

// VerifyRequest represents the JSON request body for certificate verification
type VerifyRequest struct {
	Certificate string `json:"certificate" binding:"required"`
}

// VerifyResponse represents the JSON response for certificate verification
type VerifyResponse struct {
	Valid   bool   `json:"valid"`
	Message string `json:"message"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error"`
}

func init() {
	flag.StringVar(&certPath, "cert", "", "Path to the company certificate (PEM format)")
	flag.StringVar(&privateKeyPath, "key", "", "Path to the company private key (PEM format)")
	flag.StringVar(&dnsCSVPath, "dns-csv", "", "Path to the DNS/IP whitelist CSV file")
}

func main() {
	flag.Parse()

	if certPath == "" {
		log.Fatal("Certificate path is required. Use -cert flag to specify the certificate file.")
	}

	if privateKeyPath == "" {
		log.Fatal("Private key path is required. Use -key flag to specify the private key file.")
	}

	if dnsCSVPath == "" {
		log.Fatal("DNS CSV path is required. Use -dns-csv flag to specify the CSV file.")
	}

	// Verify certificate exists
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		log.Fatalf("Certificate file does not exist: %s", certPath)
	}

	// Verify private key exists
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		log.Fatalf("Private key file does not exist: %s", privateKeyPath)
	}

	// Verify DNS CSV exists
	if _, err := os.Stat(dnsCSVPath); os.IsNotExist(err) {
		log.Fatalf("DNS CSV file does not exist: %s", dnsCSVPath)
	}

	// Load allowed DNS and IP addresses
	if err := loadDNSCSV(dnsCSVPath); err != nil {
		log.Fatalf("Failed to load DNS CSV: %v", err)
	}

	log.Printf("Using root CA certificate from: %s", certPath)
	log.Printf("Using root CA private key from: %s", privateKeyPath)
	log.Printf("Loaded %d DNS-to-IP mappings from: %s", len(dnsToIP), dnsCSVPath)

	// Setup intermediate CA (generate if doesn't exist)
	var err error
	intermediateCertPath, intermediateKeyPath, err = setupIntermediateCA(certPath, privateKeyPath)
	if err != nil {
		log.Fatalf("Failed to setup intermediate CA: %v", err)
	}

	log.Printf("Using intermediate CA certificate: %s", intermediateCertPath)
	log.Printf("Using intermediate CA private key: %s", intermediateKeyPath)

	// Setup Gin router
	router := gin.Default()

	// Encryption endpoint using openssl pkeyutl
	router.POST("/encrypt", encryptHandler)

	// Decryption endpoint using openssl pkeyutl
	router.POST("/decrypt", decryptHandler)

	// Certificate generation endpoint
	router.POST("/generate", generateHandler)

	// Certificate verification endpoint
	router.POST("/verify", verifyHandler)

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting server on port %s...", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// encryptHandler handles encryption requests using openssl pkeyutl
func encryptHandler(c *gin.Context) {
	var req EncryptRequest

	// Bind and validate request
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: fmt.Sprintf("Invalid request: %v", err),
		})
		return
	}

	// Encrypt the data using openssl pkeyutl with the certificate
	encryptedData, err := encryptWithCertificate([]byte(req.Data), certPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: fmt.Sprintf("Encryption failed: %v", err),
		})
		return
	}

	// Encode encrypted data as base64
	encodedData := base64.StdEncoding.EncodeToString(encryptedData)

	c.JSON(http.StatusOK, EncryptResponse{
		EncryptedData: encodedData,
	})
}

// generateHandler handles certificate generation requests
func generateHandler(c *gin.Context) {
	var req GenerateRequest

	// Bind and validate request
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: fmt.Sprintf("Invalid request: %v", err),
		})
		return
	}

	// Validate the config file contains allowed DNS/IP entries
	if err := validateConfig(req.Config); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: fmt.Sprintf("Configuration validation failed: %v", err),
		})
		return
	}

	// Generate the certificate using intermediate CA
	cert, key, err := generateCertificate(req.Config, intermediateCertPath, intermediateKeyPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: fmt.Sprintf("Certificate generation failed: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, GenerateResponse{
		Certificate: cert,
		PrivateKey:  key,
	})
}

// decryptHandler handles decryption requests using openssl pkeyutl
func decryptHandler(c *gin.Context) {
	var req DecryptRequest

	// Bind and validate request
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: fmt.Sprintf("Invalid request: %v", err),
		})
		return
	}

	// Decode base64 encrypted data
	encryptedData, err := base64.StdEncoding.DecodeString(req.EncryptedData)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: fmt.Sprintf("Invalid base64 data: %v", err),
		})
		return
	}

	// Decrypt the data using openssl pkeyutl with the private key
	decryptedData, err := decryptWithPrivateKey(encryptedData, privateKeyPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: fmt.Sprintf("Decryption failed: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, DecryptResponse{
		Data: string(decryptedData),
	})
}

// verifyHandler handles certificate verification requests
func verifyHandler(c *gin.Context) {
	var req VerifyRequest

	// Bind and validate request
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: fmt.Sprintf("Invalid request: %v", err),
		})
		return
	}

	// Verify the certificate against the root CA and intermediate CA
	valid, message, err := verifyCertificate(req.Certificate, certPath, intermediateCertPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: fmt.Sprintf("Verification error: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, VerifyResponse{
		Valid:   valid,
		Message: message,
	})
}

// decryptWithPrivateKey decrypts data using openssl pkeyutl command
func decryptWithPrivateKey(encryptedData []byte, keyPath string) ([]byte, error) {
	// Create temporary file for encrypted input data
	tmpInput, err := os.CreateTemp("", "decrypt-input-*.bin")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp input file: %w", err)
	}
	defer os.Remove(tmpInput.Name())
	defer tmpInput.Close()

	// Write encrypted data to temp file
	if _, err := tmpInput.Write(encryptedData); err != nil {
		return nil, fmt.Errorf("failed to write to temp file: %w", err)
	}
	tmpInput.Close()

	// Create temporary file for output
	tmpOutput, err := os.CreateTemp("", "decrypt-output-*.bin")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp output file: %w", err)
	}
	defer os.Remove(tmpOutput.Name())
	tmpOutput.Close()

	// Execute openssl pkeyutl command for decryption
	// openssl pkeyutl -decrypt -inkey private_key.pem -in encrypted.bin -out decrypted.txt
	cmd := exec.Command("openssl", "pkeyutl", "-decrypt", "-inkey", keyPath, "-in", tmpInput.Name(), "-out", tmpOutput.Name())

	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("openssl command failed: %w, output: %s", err, string(output))
	}

	// Read decrypted data from output file
	decryptedData, err := os.ReadFile(tmpOutput.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to read decrypted data: %w", err)
	}

	return decryptedData, nil
}

// encryptWithCertificateCMS encrypts data using openssl cms command for large data
func encryptWithCertificateCMS(plainData []byte, certPath string) ([]byte, error) {
	// Create temporary file for plain input data
	tmpInput, err := os.CreateTemp("", "encrypt-input-*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp input file: %w", err)
	}
	defer os.Remove(tmpInput.Name())
	defer tmpInput.Close()

	// Write plain data to temp file
	if _, err := tmpInput.Write(plainData); err != nil {
		return nil, fmt.Errorf("failed to write to temp file: %w", err)
	}
	tmpInput.Close()

	// Create temporary file for output
	tmpOutput, err := os.CreateTemp("", "encrypt-output-*.bin")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp output file: %w", err)
	}
	defer os.Remove(tmpOutput.Name())
	tmpOutput.Close()

	// Execute openssl cms command for encryption
	// openssl cms -encrypt -in plaintext.txt -out encrypted.bin -outform DER -recip cert.pem
	cmd := exec.Command("openssl", "cms", "-encrypt", "-in", tmpInput.Name(), "-out", tmpOutput.Name(), "-outform", "DER", "-recip", certPath)

	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("openssl command failed: %w, output: %s", err, string(output))
	}

	// Read encrypted data from output file
	encryptedData, err := os.ReadFile(tmpOutput.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted data: %w", err)
	}

	return encryptedData, nil
}

// encryptWithCertificate encrypts data using openssl pkeyutl command
func encryptWithCertificate(plainData []byte, certPath string) ([]byte, error) {
	// Create temporary file for plain input data
	tmpInput, err := os.CreateTemp("", "encrypt-input-*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp input file: %w", err)
	}
	defer os.Remove(tmpInput.Name())
	defer tmpInput.Close()

	// Write plain data to temp file
	if _, err := tmpInput.Write(plainData); err != nil {
		return nil, fmt.Errorf("failed to write to temp file: %w", err)
	}
	tmpInput.Close()

	// Create temporary file for output
	tmpOutput, err := os.CreateTemp("", "encrypt-output-*.bin")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp output file: %w", err)
	}
	defer os.Remove(tmpOutput.Name())
	tmpOutput.Close()

	// Execute openssl pkeyutl command for encryption
	// openssl pkeyutl -encrypt -pubin -inkey cert.pem -in plaintext.txt -out encrypted.bin
	// Note: For X.509 certificates, we need to extract the public key first
	// We'll use -certin flag to indicate we're using a certificate
	cmd := exec.Command("openssl", "pkeyutl", "-encrypt", "-certin", "-inkey", certPath, "-in", tmpInput.Name(), "-out", tmpOutput.Name())

	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("openssl command failed: %w, output: %s", err, string(output))
	}

	// Read encrypted data from output file
	encryptedData, err := os.ReadFile(tmpOutput.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted data: %w", err)
	}

	return encryptedData, nil
}

// loadDNSCSV loads DNS-to-IP mappings from a CSV file
// Expected CSV format: domain,ip (e.g., "example.com,192.168.1.1")
func loadDNSCSV(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open CSV file: %w", err)
	}
	defer file.Close()

	dnsToIP = make(map[string]string)

	reader := csv.NewReader(file)
	reader.TrimLeadingSpace = true

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read CSV record: %w", err)
		}

		if len(record) < 2 {
			continue // Skip invalid records
		}

		domain := strings.TrimSpace(record[0])
		ip := strings.TrimSpace(record[1])

		dnsToIP[domain] = ip
	}

	return nil
}

// validateConfig validates that DNS names and IP addresses in the config match the CSV mappings
func validateConfig(configContent string) error {
	// Regular expressions to extract DNS names and IP addresses from config
	dnsPattern := regexp.MustCompile(`DNS(?:\.\d+)?\s*=\s*([^\s,]+)`)
	ipPattern := regexp.MustCompile(`IP(?:\.\d+)?\s*=\s*([^\s,]+)`)

	// Extract DNS names and IPs
	dnsMatches := dnsPattern.FindAllStringSubmatch(configContent, -1)
	ipMatches := ipPattern.FindAllStringSubmatch(configContent, -1)

	// Collect all DNS names and IPs from config
	var dnsNames []string
	var ipAddrs []string

	for _, match := range dnsMatches {
		if len(match) > 1 {
			dnsNames = append(dnsNames, strings.TrimSpace(match[1]))
		}
	}

	for _, match := range ipMatches {
		if len(match) > 1 {
			ipAddrs = append(ipAddrs, strings.TrimSpace(match[1]))
		}
	}

	// Validate that we have at least one DNS and one IP
	if len(dnsNames) == 0 || len(ipAddrs) == 0 {
		return fmt.Errorf("config must contain at least one DNS name and one IP address")
	}

	// Validate each DNS-IP pair
	for _, dnsName := range dnsNames {
		expectedIP, exists := dnsToIP[dnsName]
		if !exists {
			return fmt.Errorf("DNS Challenge failed.")
		}

		// Check if the expected IP is in the provided IPs
		found := false
		for _, ipAddr := range ipAddrs {
			if ipAddr == expectedIP {
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("DNS challenge failed.")
		}
	}

	return nil
}

// generateCertificate generates a certificate and private key based on the config,
// signs it with the provided CA, encrypts both with the CA certificate, and stores them in the certificates folder
func generateCertificate(configContent, caCertPath, caKeyPath string) (string, string, error) {
	// Create certificates directory if it doesn't exist
	certsDir := "certificates"
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		return "", "", fmt.Errorf("failed to create certificates directory: %w", err)
	}

	// Create temporary directory for certificate generation
	tmpDir, err := os.MkdirTemp("", "cert-gen-*")
	if err != nil {
		return "", "", fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Write config to temporary file
	configPath := fmt.Sprintf("%s/cert.conf", tmpDir)
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		return "", "", fmt.Errorf("failed to write config file: %w", err)
	}

	// Generate private key
	keyPath := fmt.Sprintf("%s/private.key", tmpDir)
	cmd := exec.Command("openssl", "genrsa", "-out", keyPath, "2048")
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %w, output: %s", err, string(output))
	}

	// Generate CSR (Certificate Signing Request)
	csrPath := fmt.Sprintf("%s/cert.csr", tmpDir)
	cmd = exec.Command("openssl", "req", "-new", "-key", keyPath, "-out", csrPath, "-config", configPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("failed to generate CSR: %w, output: %s", err, string(output))
	}

	// Sign the CSR with the CA certificate
	certPath := fmt.Sprintf("%s/cert.pem", tmpDir)
	cmd = exec.Command("openssl", "x509", "-req", "-in", csrPath, "-CA", caCertPath, "-CAkey", caKeyPath,
		"-CAcreateserial", "-out", certPath, "-days", "365", "-sha256", "-extensions", "v3_req",
		"-extfile", configPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("failed to sign certificate: %w, output: %s", err, string(output))
	}

	// Read generated certificate
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to read certificate: %w", err)
	}

	// Read generated private key
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to read private key: %w", err)
	}

	// Encrypt the certificate with the root certificate using CMS
	encryptedCert, err := encryptWithCertificateCMS(certData, caCertPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to encrypt certificate: %w", err)
	}

	// Encrypt the private key with the root certificate using CMS
	encryptedKey, err := encryptWithCertificateCMS(keyData, caCertPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to encrypt private key: %w", err)
	}

	// Generate unique filenames based on timestamp
	timestamp := fmt.Sprintf("%d", os.Getpid())
	encryptedCertPath := fmt.Sprintf("%s/cert_%s.enc", certsDir, timestamp)
	encryptedKeyPath := fmt.Sprintf("%s/key_%s.enc", certsDir, timestamp)

	// Write encrypted certificate to file
	if err := os.WriteFile(encryptedCertPath, encryptedCert, 0600); err != nil {
		return "", "", fmt.Errorf("failed to write encrypted certificate: %w", err)
	}

	// Write encrypted private key to file
	if err := os.WriteFile(encryptedKeyPath, encryptedKey, 0600); err != nil {
		return "", "", fmt.Errorf("failed to write encrypted private key: %w", err)
	}

	return string(certData), string(keyData), nil
}

// setupIntermediateCA generates an intermediate CA certificate signed by the root CA
// if it doesn't already exist. Returns paths to the intermediate cert and key.
func setupIntermediateCA(rootCertPath, rootKeyPath string) (string, string, error) {
	// Define intermediate CA file paths in the same directory as the executable
	intermediateCert := "intermediate-ca-cert.pem"
	intermediateKey := "intermediate-ca-key.pem"

	// Check if intermediate CA already exists
	if _, err := os.Stat(intermediateCert); err == nil {
		if _, err := os.Stat(intermediateKey); err == nil {
			log.Printf("Using existing intermediate CA: %s", intermediateCert)
			return intermediateCert, intermediateKey, nil
		}
	}

	log.Println("Intermediate CA not found. Generating new intermediate CA...")

	// Create intermediate CA configuration
	intermediateConf := `[req]
distinguished_name = req_distinguished_name
prompt = no

[req_distinguished_name]
C = US
ST = State
L = City
O = Intermediate CA Organization
OU = Intermediate CA Unit
CN = Intermediate CA

[v3_intermediate_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
`

	// Write configuration to temporary file
	tmpConf, err := os.CreateTemp("", "intermediate-ca-*.conf")
	if err != nil {
		return "", "", fmt.Errorf("failed to create temp config file: %w", err)
	}
	defer os.Remove(tmpConf.Name())

	if _, err := tmpConf.WriteString(intermediateConf); err != nil {
		return "", "", fmt.Errorf("failed to write config: %w", err)
	}
	tmpConf.Close()

	// Generate intermediate CA private key
	log.Println("Generating intermediate CA private key (4096-bit RSA)...")
	cmd := exec.Command("openssl", "genrsa", "-out", intermediateKey, "4096")
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("failed to generate intermediate key: %w, output: %s", err, string(output))
	}

	// Set proper permissions on private key
	if err := os.Chmod(intermediateKey, 0600); err != nil {
		return "", "", fmt.Errorf("failed to set key permissions: %w", err)
	}

	// Generate CSR for intermediate CA
	log.Println("Generating intermediate CA certificate signing request...")
	tmpCSR, err := os.CreateTemp("", "intermediate-ca-*.csr")
	if err != nil {
		return "", "", fmt.Errorf("failed to create temp CSR file: %w", err)
	}
	defer os.Remove(tmpCSR.Name())
	tmpCSR.Close()

	cmd = exec.Command("openssl", "req", "-new", "-key", intermediateKey, "-out", tmpCSR.Name(), "-config", tmpConf.Name())
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("failed to generate CSR: %w, output: %s", err, string(output))
	}

	// Sign intermediate CA certificate with root CA
	log.Println("Signing intermediate CA certificate with root CA...")
	cmd = exec.Command("openssl", "x509", "-req", "-in", tmpCSR.Name(),
		"-CA", rootCertPath, "-CAkey", rootKeyPath,
		"-CAcreateserial", "-out", intermediateCert,
		"-days", "3650", "-sha256",
		"-extensions", "v3_intermediate_ca",
		"-extfile", tmpConf.Name())
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("failed to sign intermediate certificate: %w, output: %s", err, string(output))
	}

	// Set proper permissions on certificate
	if err := os.Chmod(intermediateCert, 0644); err != nil {
		return "", "", fmt.Errorf("failed to set cert permissions: %w", err)
	}

	// Verify the intermediate certificate
	log.Println("Verifying intermediate CA certificate...")
	cmd = exec.Command("openssl", "verify", "-CAfile", rootCertPath, intermediateCert)
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("intermediate certificate verification failed: %w, output: %s", err, string(output))
	}

	log.Printf("Intermediate CA generated successfully:")
	log.Printf("  Certificate: %s", intermediateCert)
	log.Printf("  Private Key: %s", intermediateKey)

	return intermediateCert, intermediateKey, nil
}

// verifyCertificate verifies that a certificate was signed by the root CA
func verifyCertificate(certContent, caCertPath, intermediateCertPath string) (bool, string, error) {
	// Create temporary file for the certificate to verify
	tmpCert, err := os.CreateTemp("", "verify-cert-*.pem")
	if err != nil {
		return false, "", fmt.Errorf("failed to create temp certificate file: %w", err)
	}
	defer os.Remove(tmpCert.Name())
	defer tmpCert.Close()

	// Write certificate to temp file
	if _, err := tmpCert.WriteString(certContent); err != nil {
		return false, "", fmt.Errorf("failed to write certificate to temp file: %w", err)
	}
	tmpCert.Close()

	// Execute openssl verify command with intermediate certificate
	// openssl verify -CAfile root-ca-cert.pem -untrusted intermediate-ca-cert.pem cert-to-verify.pem
	cmd := exec.Command("openssl", "verify", "-CAfile", caCertPath, "-untrusted", intermediateCertPath, tmpCert.Name())
	output, err := cmd.CombinedOutput()

	outputStr := strings.TrimSpace(string(output))

	// Check if verification succeeded
	// OpenSSL outputs "filename: OK" on success
	if err == nil && strings.Contains(outputStr, ": OK") {
		return true, "Certificate is valid and was signed by the intermediate CA", nil
	}

	// Verification failed
	if err != nil {
		// Extract meaningful error message from OpenSSL output
		return false, fmt.Sprintf("Certificate verification failed: %s", outputStr), nil
	}

	return false, "Certificate verification failed", nil
}
