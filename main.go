package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

func encryptWithKMS(plainText string, kmsKeyID string) (string, error) {
	// Load the AWS SDK configuration
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return "", fmt.Errorf("unable to load SDK config, %v", err)
	}

	// Create a new KMS client
	kmsClient := kms.NewFromConfig(cfg)

	// Create the Encrypt request
	encryptInput := &kms.EncryptInput{
		KeyId:     aws.String(kmsKeyID),
		Plaintext: []byte(plainText),
	}

	// Call the KMS Encrypt API
	encryptResp, err := kmsClient.Encrypt(context.TODO(), encryptInput)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt data: %v", err)
	}

	// The ciphertext is returned as a byte slice, so we need to base64 encode it for storage or transmission
	encodedCiphertext := base64.StdEncoding.EncodeToString(encryptResp.CiphertextBlob)

	return encodedCiphertext, nil
}

func main() {
	// Example plaintext string to encrypt
	plainText := "{\"id\":\"whe_3d9535fbs8851shac62m0cdrtb\",\"type\":\"id.producer.deleted\",\"data\":{\"id\":\"8166e631-cc34-4a3e-97c6-85784bbc9cae\",\"npn\":\"123456789\"}}"

	// Your KMS key ID
	kmsKeyID := "arn:aws:kms:us-west-2:421929404181:key/mrk-90776a09a17c4080ba4ed6f59034d664" // Replace with your KMS Key ID

	// Encrypt the data
	encryptedData, err := encryptWithKMS(plainText, kmsKeyID)
	if err != nil {
		log.Fatalf("Error encrypting data: %v", err)
	}

	// Print the base64-encoded ciphertext
	fmt.Println("Encrypted data (Base64):", encryptedData)
}
