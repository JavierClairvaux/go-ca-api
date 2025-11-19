package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"

	"github.com/gin-gonic/gin"
)

var (
	certPath       string
	privateKeyPath string
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

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error"`
}

func init() {
	flag.StringVar(&certPath, "cert", "", "Path to the company certificate (PEM format)")
	flag.StringVar(&privateKeyPath, "key", "", "Path to the company private key (PEM format)")
}

func main() {
	flag.Parse()

	if certPath == "" {
		log.Fatal("Certificate path is required. Use -cert flag to specify the certificate file.")
	}

	if privateKeyPath == "" {
		log.Fatal("Private key path is required. Use -key flag to specify the private key file.")
	}

	// Verify certificate exists
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		log.Fatalf("Certificate file does not exist: %s", certPath)
	}

	// Verify private key exists
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		log.Fatalf("Private key file does not exist: %s", privateKeyPath)
	}

	log.Printf("Using certificate from: %s", certPath)
	log.Printf("Using private key from: %s", privateKeyPath)

	// Setup Gin router
	router := gin.Default()

	// Encryption endpoint using openssl pkeyutl
	router.POST("/encrypt", encryptHandler)

	// Decryption endpoint using openssl pkeyutl
	router.POST("/decrypt", decryptHandler)

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
