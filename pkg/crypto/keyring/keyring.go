package keyring

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/PumpkinSeed/heimdall/pkg/crypto/utils"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/physical"
	"github.com/hashicorp/vault/vault"
)

const (
	keyringPath = "core/keyring"
)

var (
	ErrMissingTerm = errors.New("missing term")
	ErrGCMCreate   = errors.New("failed to initialize GCM mode")
)

type Keyring struct {
	masterKey  []byte
	keys       map[uint32]*Key
	activeTerm uint32
}

type Key struct {
	Term        uint32
	Version     int
	Value       []byte
	InstallTime time.Time
	Encryptions uint64 `json:"encryptions,omitempty"`
}

// NewKeyring creates a new Keyring
func newKeyring() *Keyring {
	k := &Keyring{
		keys:       make(map[uint32]*Key),
		activeTerm: 0,
	}
	return k
}

func Init(ctx context.Context, b physical.Backend, mk []byte) (*Keyring, error) {
	out, err := b.Get(ctx, keyringPath)
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
	keyring, err := utils.BarrierDecrypt(keyringPath, gcm, out.Value)
	//defer memzero(plain)
	if err != nil {
		return nil, err
	}

	keyringDes, err := Deserialize(keyring)
	if err != nil {
		return nil, err
	}
	return keyringDes, nil
}

func Deserialize(buf []byte) (*Keyring, error) {
	// Deserialize the Keyring
	var enc vault.EncodedKeyring
	if err := jsonutil.DecodeJSON(buf, &enc); err != nil {
		return nil, fmt.Errorf("deserialization failed: %w", err)
	}

	// Create a new Keyring
	k := newKeyring()
	k.masterKey = enc.MasterKey
	//k.rotationConfig = enc.RotationConfig
	//k.rotationConfig.Sanitize()
	for _, key := range enc.Keys {
		k.keys[key.Term] = (*Key)(key)
		if key.Term > k.activeTerm {
			k.activeTerm = key.Term
		}
	}
	return k, nil
}

func (kr *Keyring) AeadForTerm(term uint32) (cipher.AEAD, error) {
	// Read the underlying Key
	key, ok := kr.keys[term]
	if !ok {
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
