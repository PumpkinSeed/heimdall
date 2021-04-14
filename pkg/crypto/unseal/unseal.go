package unseal

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/PumpkinSeed/heimdall/pkg/crypto/keyring"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/mount"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/utils"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/physical"
	"github.com/hashicorp/vault/shamir"
	"github.com/hashicorp/vault/vault"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

const (
	BarrierKeysPath    = "core/hsm/barrier-unseal-keys"
	defaultTotalShares = 5
)

type Unseal struct {
	masterKey   []byte
	keyring     *vault.Keyring
	MountID     string
	tempKeys    [][]byte
	threshold   int
	TotalShares int
	sb          vault.SecurityBarrier
	b           physical.Backend
	storage     logical.Storage // TODO consider to add default value to this, which checks unseal status and returns error if sealed
}

var (
	u *Unseal
)

func Get() *Unseal {
	if u == nil {
		u = &Unseal{
			TotalShares: defaultTotalShares,
		}
	}
	return u
}

func (u *Unseal) Init(t int) {
	u.threshold = t
}

func (u *Unseal) SetSecurityBarrier(b vault.SecurityBarrier) {
	u.sb = b
}

func (u *Unseal) SetBackend(b physical.Backend) {
	u.b = b
}

// First step to start the server
func (u *Unseal) Unseal(ctx context.Context, key string) (bool, error) {
	defer u.cleanTempKeys()
	if len(u.tempKeys) < u.threshold {
		rk, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			return false, err
		}
		u.tempKeys = append(u.tempKeys, rk)
	}
	if len(u.tempKeys) >= u.threshold {
		return true, u.unseal(ctx)
	}

	return false, nil
}

// Keyring is getting keyring from database and decrypt it with the master key
func (u *Unseal) Keyring(ctx context.Context) error {
	if u.masterKey == nil {
		return errors.New("server is still sealed, unseal it before do anything")
	}
	k, err := keyring.Init(ctx, u.b, u.masterKey)
	if err != nil {
		return err
	}

	u.keyring = k

	return nil
}

// Mount is mounting transit, getting the MountTable from database and decrypt it
func (u *Unseal) Mount(ctx context.Context) (string, error) {
	if u.masterKey == nil {
		return "", errors.New("server is still sealed, unseal it before do anything")
	}
	if u.keyring == nil {
		return "", errors.New("missing keyring, init keyring first")
	}

	table, err := mount.Mount(ctx, u.b, u.keyring)
	if err != nil {
		return "", err
	}

	for _, e := range table.Entries {
		if strings.EqualFold(e.Type, "transit") {
			u.MountID = e.UUID

			return e.ViewPath(), nil
		}
	}

	return "", errors.New("missing transit entry")
}

func (u *Unseal) Status() Status {
	sealed, err := u.sb.Sealed()
	if err != nil {
		log.Error(err)
	}
	log.Debugf("Sealed: %v", sealed)
	return Status{
		TotalShares: 5, // TODO make this configurable
		Threshold:   u.threshold,
		Process:     len(u.tempKeys),
		Unsealed:    u.masterKey != nil,
	}
}

func (u *Unseal) unseal(ctx context.Context) error {
	masterData, err := u.b.Get(ctx, BarrierKeysPath)
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

func (u *Unseal) PostProcess(ctx context.Context, barrierPath string) error {
	// TODO check seal key passing
	if err := u.sb.Initialize(ctx, u.masterKey, []byte{}, rand.Reader); err != nil && !errors.Is(err, vault.ErrBarrierAlreadyInit) {
		return err
	}

	if err := u.sb.Unseal(ctx, u.masterKey); err != nil {
		return err
	}

	u.storage = vault.NewBarrierView(u.sb, barrierPath)
	return nil
}

func (u *Unseal) cleanTempKeys() {
	if len(u.tempKeys) >= u.threshold {
		for _, key := range u.tempKeys {
			utils.Memzero(key)
		}
		u.tempKeys = [][]byte{}
	}
}

func (u *Unseal) Storage() logical.Storage {
	return u.storage
}
