package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

type Envelope struct {
	Nonce [12]byte
	Data  []byte
}

func DeriveKey(passphrase []byte, salt []byte) []byte {
	h := sha256.New()
	h.Write(passphrase)
	h.Write(salt)
	return h.Sum(nil)
}

func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	return key, nil
}

func Encrypt(key []byte, plaintext []byte) (*Envelope, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	env := &Envelope{}
	copy(env.Nonce[:], nonce)
	env.Data = ciphertext
	return env, nil
}

func Decrypt(key []byte, env *Envelope) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}

	plaintext, err := gcm.Open(nil, env.Nonce[:], env.Data, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

func EncryptWithPassphrase(passphrase []byte, plaintext []byte) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	key := DeriveKey(passphrase, salt)
	env, err := Encrypt(key, plaintext)
	if err != nil {
		return nil, err
	}

	result := make([]byte, 0, 16+12+len(env.Data))
	result = append(result, salt...)
	result = append(result, env.Nonce[:]...)
	result = append(result, env.Data...)
	return result, nil
}

func DecryptWithPassphrase(passphrase []byte, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 28 { // 16 salt + 12 nonce minimum
		return nil, fmt.Errorf("ciphertext too short")
	}

	salt := ciphertext[:16]
	nonce := ciphertext[16:28]
	data := ciphertext[28:]

	key := DeriveKey(passphrase, salt)
	env := &Envelope{
		Data: data,
	}
	copy(env.Nonce[:], nonce)

	return Decrypt(key, env)
}
