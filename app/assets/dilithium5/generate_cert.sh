#!/bin/bash

# Prompt for the algorithm
echo "Enter the algorithm (e.g., dilithium3):"
read algorithm

# Validate input
if [ -z "$algorithm" ]; then
    echo "Error: No algorithm provided."
    exit 1
fi

# Define filenames based on the algorithm
KEY_FILE="${algorithm}_srv.key"
CSR_FILE="${algorithm}_srv.csr"
CRT_FILE="${algorithm}_srv.crt"
CA_CRT_FILE="../ca/dilithium3_CA.crt"
CA_KEY_FILE="../ca/dilithium3_CA.key"
CA_SERIAL_FILE="../ca/dilithium3_CA.srl"

# Paths and config
OPENSSL_CONFIG="/usr/local/ssl/openssl.cnf"

# Generate a private key and CSR
echo "Generating private key and CSR for $algorithm..."
openssl req -new -newkey "$algorithm" -keyout "$KEY_FILE" -out "$CSR_FILE" -nodes -subj "/CN=test.example.com" -config "$OPENSSL_CONFIG"

if [ $? -ne 0 ]; then
    echo "Error: Failed to generate private key or CSR."
    exit 1
fi

# Sign the CSR with the CA certificate and key to create the certificate
echo "Signing CSR with CA certificate..."
openssl x509 -req -in "$CSR_FILE" -out "$CRT_FILE" -CA "$CA_CRT_FILE" -CAkey "$CA_KEY_FILE" -CAcreateserial -days 365

if [ $? -ne 0 ]; then
    echo "Error: Failed to sign the CSR."
    exit 1
fi

# Verify the generated certificate against the CA certificate
echo "Verifying the certificate..."
openssl verify -CAfile "$CA_CRT_FILE" "$CRT_FILE"

if [ $? -ne 0 ]; then
    echo "Error: Certificate verification failed."
    exit 1
fi

echo "Certificate generation completed."
echo "Generated files:"
echo "  Private Key: $KEY_FILE"
echo "  CSR:         $CSR_FILE"
echo "  Certificate: $CRT_FILE"

