package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	plaintext := []byte("sy3nc@ll{v01d} direct syscall test payload")

	env, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	decrypted, err := Decrypt(key, env)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("round-trip mismatch: got %q", decrypted)
	}
}

func TestEncryptWithPassphrase(t *testing.T) {
	passphrase := []byte("voidsec-do-not-use-this")
	plaintext := []byte("https://example.com/api/v2/health")

	ct, err := EncryptWithPassphrase(passphrase, plaintext)
	if err != nil {
		t.Fatalf("EncryptWithPassphrase: %v", err)
	}

	pt, err := DecryptWithPassphrase(passphrase, ct)
	if err != nil {
		t.Fatalf("DecryptWithPassphrase: %v", err)
	}

	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("round-trip mismatch: got %q", pt)
	}
}

func TestEncryptTamper(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	plaintext := []byte("sentinel")

	env, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	env.Data[0] ^= 0xFF

	_, err = Decrypt(key, env)
	if err == nil {
		t.Fatal("expected authentication error on tampered ciphertext")
	}
}