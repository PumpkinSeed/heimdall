package unseal

import (
	"context"
	"encoding/base64"
	"encoding/json"

	"github.com/PumpkinSeed/heimdall/internal/crypto/keyring"
	"github.com/PumpkinSeed/heimdall/internal/crypto/utils"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	"github.com/hashicorp/vault/sdk/physical"
	"github.com/hashicorp/vault/shamir"
	"google.golang.org/protobuf/proto"
)

const (
	threshold = 3

	storedBarrierKeysPath = "core/hsm/barrier-unseal-keys"
)

type unseal struct {
	masterKey []byte
	keyring   *keyring.Keyring
}

var (
	tempKeys [][]byte
	u        *unseal
)

func Get() *unseal {
	if u == nil {
		u = &unseal{}
	}
	return u
}

func (u *unseal) Unseal(ctx context.Context, b physical.Backend, key string) error {
	defer cleanTempKeys()
	if len(tempKeys) < threshold {
		rk, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			return err
		}
		tempKeys = append(tempKeys, rk)
	}
	if len(tempKeys) == threshold {
		return u.unseal(ctx, b)
	}

	return nil
}

func (u *unseal) InitKeyring(ctx context.Context, b physical.Backend) error {
	k, err := keyring.Init(ctx, b, u.masterKey)
	if err != nil {
		return err
	}

	u.keyring = k

	return nil
}

func (u *unseal) unseal(ctx context.Context, b physical.Backend) error {
	masterData, err := b.Get(ctx, storedBarrierKeysPath)
	if err != nil {
		return err
	}
	unsealed, err := shamir.Combine(tempKeys)
	if err != nil {
		return err
	}

	w := aead.ShamirWrapper{
		Wrapper: aead.NewWrapper(&wrapping.WrapperOptions{}),
	}
	if err := w.SetAESGCMKeyBytes(unsealed); err != nil {
		return err
	}

	blobInfo := &wrapping.EncryptedBlobInfo{}
	if err := proto.Unmarshal(masterData.Value, blobInfo); err != nil {
		return err
	}

	pt, err := w.Decrypt(ctx, blobInfo, nil)
	if err != nil {
		return err
	}

	var keys [][]byte
	if err := json.Unmarshal(pt, &keys); err != nil {
		return err
	}

	u.masterKey = keys[0]

	return nil
}

func cleanTempKeys() {
	if len(tempKeys) >= threshold {
		for _, key := range tempKeys {
			utils.Memzero(key)
		}
		tempKeys = [][]byte{}
	}
}
