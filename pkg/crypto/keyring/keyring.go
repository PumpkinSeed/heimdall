package keyring

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"

	"github.com/PumpkinSeed/heimdall/internal/errors"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/utils"
	"github.com/hashicorp/vault/sdk/physical"
	"github.com/hashicorp/vault/vault"
)

const (
	Path = "core/keyring"
)

var (
	ErrMissingTerm     = errors.New("missing term", errors.CodePkgCryptoKeyringAeadForTermMissingTerm)
	ErrTermMisMatch    = errors.New("term mis-match", errors.CodePkgCryptoKeyringInitTermMisMatch)
	ErrGCMCreate       = errors.New("failed to initialize GCM mode", errors.CodePkgCryptoKeyringAeadFromKeyGCMCreate)
	ErrKeyringNotFound = errors.New("keyring not found", errors.CodePkgCryptoKeyringInitNotFound)
)

func Init(ctx context.Context, b physical.Backend, mk []byte) (*vault.Keyring, error) {
	out, err := b.Get(ctx, Path)
	if err != nil {
		return nil, errors.Wrap(err, "keyring database get error", errors.CodePkgCryptoKeyring)
	}
	if out == nil {
		return nil, ErrKeyringNotFound
	}

	// Verify the term is always just one
	// initialKeyTerm
	if term := binary.BigEndian.Uint32(out.Value[:4]); term != 1 {
		return nil, ErrTermMisMatch
	}

	gcm, err := AeadFromKey(mk)
	if err != nil {
		return nil, errors.Wrap(err, "keyring AEAD creation error", errors.CodePkgCryptoKeyringAeadFromKey)
	}

	// Decrypt the barrier init key
	keyring, err := utils.BarrierDecrypt(Path, gcm, out.Value)
	defer utils.Memzero(keyring)
	if err != nil {
		return nil, errors.Wrap(err, "keyring barrier decrypt error", errors.CodePkgCryptoKeyringBarrierDecrypt)
	}

	keyringDes, err := vault.DeserializeKeyring(keyring)
	if err != nil {
		return nil, errors.Wrap(err, "keyring deserialize error", errors.CodePkgCryptoKeyringDeserialize)
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
		return nil, errors.Wrap(err, "keyring aead for term from key error", errors.CodePkgCryptoKeyringAeadForTermFromKey)
	}

	return aead, nil
}

func AeadFromKey(key []byte) (cipher.AEAD, error) {
	// Create the AES cipher
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create cipher", errors.CodePkgCryptoKeyringAeadFromKeyCipherCreate)
	}

	// Create the GCM mode AEAD
	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, ErrGCMCreate
	}
	return gcm, nil
}
