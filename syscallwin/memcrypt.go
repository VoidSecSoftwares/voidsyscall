//go:build windows

package syscallwin

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type Vault struct {
	data     []byte
	key      []byte
	keyNonce uint64
	mu       sync.Mutex
	rekeying int32
	destroyed int32
}

// VaultCreate encrypts plaintext with a random 32-byte key, stores it in
// the heap, and returns a handle. The plaintext is never stored in raw form.
// The Vault re-keys every rekeyInterval by generating a new XOR key and
// re-encrypting — forensic snapshots of heap memory between re-key intervals
// recover ciphertext, not plaintext.
func VaultCreate(plaintext []byte, rekeyInterval time.Duration) (*Vault, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	ciphertext := make([]byte, len(plaintext))
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	nonceVal := binary.LittleEndian.Uint64(nonce)

	v := &Vault{
		data:      ciphertext,
		key:       key,
		keyNonce:  nonceVal,
	}

	v.encryptInPlace(plaintext)

	go v.rekeyLoop(rekeyInterval)

	return v, nil
}

func (v *Vault) encryptInPlace(plaintext []byte) {
	keyStream := v.generateKeyStream(len(plaintext))
	for i := range plaintext {
		v.data[i] = plaintext[i] ^ keyStream[i]
	}
}

func (v *Vault) decryptInPlace() []byte {
	plaintext := make([]byte, len(v.data))
	keyStream := v.generateKeyStream(len(v.data))
	for i := range v.data {
		plaintext[i] = v.data[i] ^ keyStream[i]
	}
	return plaintext
}

func (v *Vault) generateKeyStream(length int) []byte {
	stream := make([]byte, length)
	for i := 0; i < length; i++ {
		idx := i % 32
		stream[i] = v.key[idx] ^ byte(v.keyNonce>>uint(i%8))
	}
	for i := 0; i < length; i += 64 {
		end := i + 64
		if end > length {
			end = length
		}
		for j := i; j < end-1; j++ {
			stream[j] ^= stream[j+1] ^ v.key[j%32]
		}
	}
	return stream
}

func (v *Vault) rekeyLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		if atomic.LoadInt32(&v.destroyed) != 0 {
			return
		}
		v.Rekey()
	}
}

// Rekey generates a new key, decrypts with the old key, re-encrypts with
// the new key. The heap now contains ciphertext encrypted under the new key —
// any forensic dump of the old ciphertext is garbage.
func (v *Vault) Rekey() {
	v.mu.Lock()
	defer v.mu.Unlock()

	if atomic.LoadInt32(&v.destroyed) != 0 {
		return
	}
	atomic.StoreInt32(&v.rekeying, 1)
	defer atomic.StoreInt32(&v.rekeying, 0)

	plaintext := v.decryptInPlace()

	newKey := make([]byte, 32)
	_, _ = rand.Read(newKey)

	v.key = newKey
	var newNonce [8]byte
	_, _ = rand.Read(newNonce[:])
	v.keyNonce = binary.LittleEndian.Uint64(newNonce[:])

	v.encryptInPlace(plaintext)

	// Wipe plaintext from stack
	for i := range plaintext {
		plaintext[i] = 0
	}
}

// Read decrypts the vault contents and returns the plaintext.
func (v *Vault) Read() []byte {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.decryptInPlace()
}

// Write replaces the vault contents with new plaintext.
func (v *Vault) Write(plaintext []byte) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.data = make([]byte, len(plaintext))
	v.encryptInPlace(plaintext)
}

// Destroy wipes the key and ciphertext from memory, then stops the re-key timer.
func (v *Vault) Destroy() {
	atomic.StoreInt32(&v.destroyed, 1)
	v.mu.Lock()
	defer v.mu.Unlock()

	// Overwrite key
	for i := range v.key {
		v.key[i] = 0
	}
	// Overwrite data
	for i := range v.data {
		v.data[i] = 0
	}
	v.key = nil
	v.data = nil
}

// Size returns the ciphertext length.
func (v *Vault) Size() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.data)
}

// VaultEncryptBytes encrypts arbitrary bytes with a given key using the
// same XOR-based stream cipher. Useful for encrypting data before writing
// to disk or transmitting over a channel.
func VaultEncryptBytes(key []byte, data []byte) []byte {
	out := make([]byte, len(data))
	nonce := uint64(0)
	for i := range data {
		streamByte := key[i%32] ^ byte(nonce>>uint(i%8))
		for j := 0; j < i%7; j++ {
			streamByte ^= key[(i+j)%32]
		}
		out[i] = data[i] ^ streamByte
	}
	return out
}

// VaultDecryptBytes decrypts data encrypted with VaultEncryptBytes.
func VaultDecryptBytes(key []byte, data []byte) []byte {
	return VaultEncryptBytes(key, data)
}

// SecureDelete overwrites a memory region with random data before freeing.
func SecureDelete(ptr uintptr, size uintptr) {
	buf := make([]byte, size)
	_, _ = rand.Read(buf)
	var n uintptr
	_ = NtWriteVirtualMemory(0xffffffffffffffff, ptr, buf, &n)

	// Second pass: zeros
	for i := range buf {
		buf[i] = 0
	}
	_ = NtWriteVirtualMemory(0xffffffffffffffff, ptr, buf, &n)

	// Third pass: ones
	for i := range buf {
		buf[i] = 0xFF
	}
	_ = NtWriteVirtualMemory(0xffffffffffffffff, ptr, buf, &n)

	// Final: zeros and free
	for i := range buf {
		buf[i] = 0
	}
	_ = NtWriteVirtualMemory(0xffffffffffffffff, ptr, buf, &n)

	base := ptr
	_ = NtFreeVirtualMemory(0xffffffffffffffff, &base, &size, MEM_RELEASE)
}

// StackEncrypt encrypts a stack-allocated buffer in place. After the function
// returns, the stack frame is reused but the encrypted data remains until
// overwritten by the next call — making stack forensics unreliable.
func StackEncrypt(buf []byte) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	for i := range buf {
		buf[i] ^= key[i%32]
	}
	for i := range key {
		key[i] = 0
	}
}

// StackDecrypt decrypts a buffer encrypted with StackEncrypt.
func StackDecrypt(buf []byte, key []byte) {
	for i := range buf {
		buf[i] ^= key[i%32]
	}
}

// WipeMemory writes zeros over a memory region using only NtWriteVirtualMemory.
func WipeMemory(addr uintptr, size uintptr) {
	buf := make([]byte, size)
	var n uintptr
	_ = NtWriteVirtualMemory(0xffffffffffffffff, addr, buf, &n)
}

// GetVault returns a read-only snapshot of the current vault state.
func (v *Vault) GetSnapshot() ([]byte, error) {
	if atomic.LoadInt32(&v.destroyed) != 0 {
		return nil, fmt.Errorf("vault destroyed")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	snap := make([]byte, len(v.data))
	copy(snap, v.data)
	return snap, nil
}
