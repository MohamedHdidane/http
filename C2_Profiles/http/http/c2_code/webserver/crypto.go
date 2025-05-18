package webserver

import (
    "crypto/rand"
    "encoding/base64"
    "errors"
    "golang.org/x/crypto/chacha20poly1305"
    "golang.org/x/crypto/hkdf"
    "hash"
    "io"
    "log"
    "github.com/MythicMeta/MythicContainer/logging"
)

type EncryptionHandler struct {
    Key []byte
    Type string
}

// NewEncryptionHandler initializes an encryption handler with the provided key and type
func NewEncryptionHandler(key string, encType string) (*EncryptionHandler, error) {
    rawKey, err := base64.StdEncoding.DecodeString(key)
    if err != nil {
        return nil, err
    }
    if len(rawKey) != 16 && len(rawKey) != 24 && len(rawKey) != 32 {
        return nil, errors.New("invalid key length: must be 16, 24, or 32 bytes")
    }

    // Derive a 32-byte key using HKDF for ChaCha20-Poly1305
    hkdf := hkdf.New(sha256.New, rawKey, nil, []byte("igider_encryption"))
    derivedKey := make([]byte, 32)
    if _, err := io.ReadFull(hkdf, derivedKey); err != nil {
        return nil, err
    }

    return &EncryptionHandler{
        Key: derivedKey,
        Type: encType,
    }, nil
}

// Encrypt encrypts the input data based on the encryption type
func (e *EncryptionHandler) Encrypt(data []byte) ([]byte, error) {
    if e.Type == "none" || len(data) == 0 {
        return data, nil
    }

    if e.Type == "chacha20_poly1305" {
        // Initialize ChaCha20-Poly1305 AEAD
        aead, err := chacha20poly1305.New(e.Key)
        if err != nil {
            return nil, err
        }

        // Generate a 12-byte nonce
        nonce := make([]byte, aead.NonceSize())
        if _, err := rand.Read(nonce); err != nil {
            return nil, err
        }

        // Encrypt the data
        ciphertext := aead.Seal(nil, nonce, data, nil)

        // Return nonce + ciphertext
        return append(nonce, ciphertext...), nil
    }

    // Add handling for aes256_hmac if needed
    return nil, errors.New("unsupported encryption type")
}

// Decrypt decrypts the input data based on the encryption type
func (e *EncryptionHandler) Decrypt(data []byte) ([]byte, error) {
    if e.Type == "none" || len(data) == 0 {
        return data, nil
    }

    if e.Type == "chacha20_poly1305" {
        // Initialize ChaCha20-Poly1305 AEAD
        aead, err := chacha20poly1305.New(e.Key)
        if err != nil {
            return nil, err
        }

        // Extract nonce and ciphertext
        if len(data) < aead.NonceSize() {
            return nil, errors.New("invalid ciphertext: too short")
        }
        nonce := data[:aead.NonceSize()]
        ciphertext := data[aead.NonceSize():]

        // Decrypt the data
        plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
        if err != nil {
            logging.LogError(err, "Decryption failed: invalid authentication tag")
            return nil, err
        }

        return plaintext, nil
    }

    // Add handling for aes256_hmac if needed
    return nil, errors.New("unsupported encryption type")
}