package unseal

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/PumpkinSeed/heimdall/internal/errors"
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

	ErrSealed = errors.New("operation not permitted, service is still sealed", errors.CodePkgCryptoUnsealSealed)
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
			return false, errors.Wrap(err, "unseal key invalid format", errors.CodePkgCryptoUnsealKeyFormat)
		}
		u.tempKeys = append(u.tempKeys, rk)
	}
	if len(u.tempKeys) >= u.Threshold {
		err := u.unseal(ctx)
		if err != nil {
			return false, errors.Wrap(err, "unseal error", errors.CodePkgCryptoUnseal)
		}
		return true, nil
	}

	return false, nil
}

// Keyring is getting keyring from database and decrypt it with the master key
func (u *Unseal) Keyring(ctx context.Context) error {
	if u.masterKey == nil {
		return errors.New("unseal keyring server is still sealed, unseal it before do anything", errors.CodePkgCryptoUnsealMissingMasterKey)
	}
	k, err := keyring.Init(ctx, u.Backend, u.masterKey)
	if err != nil {
		return errors.Wrap(err, "unseal keyring init error", errors.CodePkgCryptoUnsealKeyring)
	}

	u.keyring = k

	return nil
}

// Mount is mounting transit, getting the MountTable from database and decrypt it
func (u *Unseal) Mount(ctx context.Context) (map[string]string, error) {
	if u.masterKey == nil {
		return nil, errors.New("unseal keyring server is still sealed, unseal it before do anything", errors.CodePkgCryptoUnsealMissingMasterKey)
	}
	if u.keyring == nil {
		return nil, errors.New("unseal keyring missing keyring, init keyring first", errors.CodePkgCryptoUnsealKeyringMissing)
	}

	table, err := mount.Mount(ctx, u.Backend, u.keyring)
	if err != nil {
		return nil, errors.Wrap(err, "unseal mount error", errors.CodePkgCryptoUnsealMount)
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
		log.Error(errors.NewErr(err, errors.CodePkgCryptoUnsealStatus))
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
		return errors.Wrap(err, "unseal dev mode read error", errors.CodePkgCryptoUnsealDevModeRead)
	}
	u.SetMasterKey(masterKey)
	u.SetDefaultEnginePath("transit/")
	if err := u.PostProcess(ctx, map[string]string{"transit/": "logical/00000000-0000-0000-0000-000000000000"});
		err != nil {
		return errors.Wrap(err, "", errors.CodePkgCryptoUnsealDevModePostProcess)
	}
	return nil
}

func (u *Unseal) unseal(ctx context.Context) error {
	masterData, err := u.Backend.Get(ctx, BarrierKeysPath)
	if err != nil {
		return errors.Wrap(err, "unseal get key error", errors.CodePkgCryptoUnsealUnsealGetKey)
	}
	unsealed, err := shamir.Combine(u.tempKeys)
	if err != nil {
		return errors.Wrap(err, "unseal shamir combine error", errors.CodePkgCryptoUnsealUnsealShamirCombine)
	}

	w := aead.ShamirWrapper{
		Wrapper: aead.NewWrapper(&wrapping.WrapperOptions{}),
	}
	if err := w.SetAESGCMKeyBytes(unsealed); err != nil {
		return errors.Wrap(err, "unseal AES-GCM error", errors.CodePkgCryptoUnsealUnsealAESGCM)
	}

	blobInfo := &wrapping.EncryptedBlobInfo{}
	if err := proto.Unmarshal(masterData.Value, blobInfo); err != nil {
		return errors.Wrap(err, "unseal proto unmarshal error", errors.CodePkgCryptoUnsealUnsealProtoUnmarshal)
	}

	pt, err := w.Decrypt(ctx, blobInfo, nil)
	if err != nil {
		return errors.Wrap(err, "unseal decrypt error", errors.CodePkgCryptoUnsealUnseal)
	}

	var keys [][]byte
	if err := json.Unmarshal(pt, &keys); err != nil {
		return errors.Wrap(err, "unseal json unmarshal error", errors.CodePkgCryptoUnsealUnsealUnmarshal)
	}

	u.masterKey = keys[0]

	return nil
}

func (u *Unseal) PostProcess(ctx context.Context, barrierPaths map[string]string) error {
	// TODO check seal key passing
	if err := u.SecurityBarrier.Initialize(ctx, u.masterKey, []byte{}, rand.Reader); err != nil && !errors.Is(err, vault.ErrBarrierAlreadyInit) {
		return errors.Wrap(err, "unseal post process security barrier init error", errors.CodePkgCryptoUnsealPostProcessSBInitialize)
	}

	if err := u.SecurityBarrier.Unseal(ctx, u.masterKey); err != nil {
		return errors.Wrap(err, "unseal post process security barrier unseal error", errors.CodePkgCryptoUnsealPostProcessSBUnseal)
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

func (u *Unseal) CheckEngine(path string) (bool, error) {
	if _, ok := u.storage[path]; ok {
		return true, nil
	}
	sealed, err := u.SecurityBarrier.Sealed()
	if err != nil {
		return false, err
	}
	if sealed {
		return false, errors.New("heimdall is sealed")
	}
	return false, nil
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
