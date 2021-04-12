package keyring

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/PumpkinSeed/heimdall/pkg/crypto/utils"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/vault"
)

const (
	Path = "core/keyring"
)

var (
	ErrMissingTerm = errors.New("missing term")
	ErrGCMCreate   = errors.New("failed to initialize GCM mode")
)


func Init(ctx context.Context, b logical.Storage, mk []byte) (*vault.Keyring, error) {
	out, err := b.Get(ctx, Path)
	if err != nil {
		return nil, err
	}
	if out == nil {
		return nil, errors.New("keyring not found")
	}

	// Verify the term is always just one
	// initialKeyTerm
	if term := binary.BigEndian.Uint32(out.Value[:4]); term != 1 {
		return nil, errors.New("term mis-match")
	}

	gcm, err := AeadFromKey(mk)
	if err != nil {
		return nil, err
	}

	// Decrypt the barrier init key
	keyring, err := utils.BarrierDecrypt(Path, gcm, out.Value)
	defer utils.Memzero(keyring)
	if err != nil {
		return nil, err
	}

	keyringDes, err := vault.DeserializeKeyring(keyring)
	if err != nil {
		return nil, err
	}

	return keyringDes, nil
}


func AeadForTerm(kr *vault.Keyring, term uint32) (cipher.AEAD, error) {
	// Read the underlying Key
	key := kr.TermKey(term)
	if key == nil {
		return nil, ErrMissingTerm
	}

	// Create a new aead
	aead, err := AeadFromKey(key.Value)
	if err != nil {
		return nil, err
	}

	return aead, nil
}

func AeadFromKey(key []byte) (cipher.AEAD, error) {
	// Create the AES cipher
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create the GCM mode AEAD
	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, ErrGCMCreate
	}
	return gcm, nil
}
