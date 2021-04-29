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
	masterKey         []byte
	keyring           *vault.Keyring
	tempKeys          [][]byte
	Threshold         int
	TotalShares       int
	defaultEnginePath string
	SecurityBarrier   vault.SecurityBarrier
	Backend           physical.Backend
	storage           map[string]logical.Storage
}

var (
	u *Unseal

	ErrSealed = errors.New("operation not permitted, service is still sealed")
)

func Get() *Unseal {
	if u == nil {
		u = &Unseal{
			TotalShares: defaultTotalShares,
			storage:     make(map[string]logical.Storage),
		}
	}

	return u
}

func (u *Unseal) Init(t int) {
	u.Threshold = t
}

func (u *Unseal) SetSecurityBarrier(b vault.SecurityBarrier) {
	u.SecurityBarrier = b
}

func (u *Unseal) SetBackend(b physical.Backend) {
	u.Backend = b
}

// First step to start the server
func (u *Unseal) Unseal(ctx context.Context, key string) (bool, error) {
	defer u.cleanTempKeys()
	if len(u.tempKeys) < u.Threshold {
		rk, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			return false, err
		}
		u.tempKeys = append(u.tempKeys, rk)
	}
	if len(u.tempKeys) >= u.Threshold {
		return true, u.unseal(ctx)
	}

	return false, nil
}

// Keyring is getting keyring from database and decrypt it with the master key
func (u *Unseal) Keyring(ctx context.Context) error {
	if u.masterKey == nil {
		return errors.New("server is still sealed, unseal it before do anything")
	}
	k, err := keyring.Init(ctx, u.Backend, u.masterKey)
	if err != nil {
		return err
	}

	u.keyring = k

	return nil
}

// Mount is mounting transit, getting the MountTable from database and decrypt it
func (u *Unseal) Mount(ctx context.Context) (map[string]string, error) {
	if u.masterKey == nil {
		return nil, errors.New("server is still sealed, unseal it before do anything")
	}
	if u.keyring == nil {
		return nil, errors.New("missing keyring, init keyring first")
	}

	table, err := mount.Mount(ctx, u.Backend, u.keyring)
	if err != nil {
		return nil, err
	}

	res := make(map[string]string)
	for _, e := range table.Entries {
		if strings.EqualFold(e.Type, "transit") {
			res[e.Path] = e.ViewPath()
		}
	}

	return res, nil
}

func (u *Unseal) Status() Status {
	sealed, err := u.SecurityBarrier.Sealed()
	if err != nil {
		log.Error(err)
	}
	log.Debugf("Sealed: %v", sealed)
	return Status{
		TotalShares: 5, // TODO make this configurable
		Threshold:   u.Threshold,
		Process:     len(u.tempKeys),
		Unsealed:    u.masterKey != nil,
	}
}

func (u *Unseal) DevMode(ctx context.Context) error {
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	if err != nil {
		return err
	}
	u.SetMasterKey(masterKey)
	u.SetDefaultEnginePath("transit/")
	return u.PostProcess(ctx, map[string]string{"transit/":"logical/00000000-0000-0000-0000-000000000000"})
}

func (u *Unseal) unseal(ctx context.Context) error {
	masterData, err := u.Backend.Get(ctx, BarrierKeysPath)
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

func (u *Unseal) PostProcess(ctx context.Context, barrierPaths map[string]string) error {
	// TODO check seal key passing
	if err := u.SecurityBarrier.Initialize(ctx, u.masterKey, []byte{}, rand.Reader); err != nil && !errors.Is(err, vault.ErrBarrierAlreadyInit) {
		return err
	}

	if err := u.SecurityBarrier.Unseal(ctx, u.masterKey); err != nil {
		return err
	}

	for p, bp := range barrierPaths {
		u.storage[p] = vault.NewBarrierView(u.SecurityBarrier, bp)
	}
	return nil
}

func (u *Unseal) cleanTempKeys() {
	if len(u.tempKeys) >= u.Threshold {
		for _, key := range u.tempKeys {
			utils.Memzero(key)
		}
		u.tempKeys = [][]byte{}
	}
}

func (u *Unseal) Storage(path string) logical.Storage {
	if path == "" {
		path = u.defaultEnginePath
	}
	return u.storage[path]
}

// SetMasterKey is only for testing purpose
func (u *Unseal) SetMasterKey(key []byte) {
	u.masterKey = key
}

func (u *Unseal) GetKeyRing() *vault.Keyring {
	return u.keyring
}

func (u *Unseal) SetDefaultEnginePath(path string) {
	u.defaultEnginePath = path
}
