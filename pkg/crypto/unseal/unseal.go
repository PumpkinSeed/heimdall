package unseal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/PumpkinSeed/heimdall/pkg/crypto/keyring"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/mount"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/utils"
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
	MountID   string
	tempKeys  [][]byte
}

var (
	u *unseal
)

func Get() *unseal {
	if u == nil {
		u = &unseal{}
	}
	return u
}

// First step to start the server
func (u *unseal) Unseal(ctx context.Context, b physical.Backend, key string) (bool, error) {
	defer u.cleanTempKeys()
	if len(u.tempKeys) < threshold {
		rk, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			return false, err
		}
		u.tempKeys = append(u.tempKeys, rk)
	}
	if len(u.tempKeys) == threshold {
		return true, u.unseal(ctx, b)
	}

	return false, nil
}

// Keyring is getting keyring from database and decrypt it with the master key
func (u *unseal) Keyring(ctx context.Context, b physical.Backend) error {
	if u.masterKey == nil {
		return errors.New("server is still sealed, unseal it before do anything")
	}
	k, err := keyring.Init(ctx, b, u.masterKey)
	if err != nil {
		return err
	}

	u.keyring = k

	return nil
}

// Mount is mounting transit, getting the MountTable from database and decrypt it
func (u unseal) Mount(ctx context.Context, b physical.Backend) error {
	if u.masterKey == nil {
		return errors.New("server is still sealed, unseal it before do anything")
	}

	table, err := mount.Mount(ctx, b, u.keyring)
	if err != nil {
		return err
	}

	for _, e := range table.Entries {
		if strings.HasPrefix(e.Path, "transit/") {
			u.MountID = e.UUID

			break
		}
	}

	return nil
}

func (u *unseal) unseal(ctx context.Context, b physical.Backend) error {
	masterData, err := b.Get(ctx, storedBarrierKeysPath)
	if err != nil {
		return err
	}
	unsealed, err := shamir.Combine(u.tempKeys)
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

func (u *unseal) cleanTempKeys() {
	if len(u.tempKeys) >= threshold {
		for _, key := range u.tempKeys {
			utils.Memzero(key)
		}
		u.tempKeys = [][]byte{}
	}
}
