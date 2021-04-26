package init

import (
	"context"
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/PumpkinSeed/heimdall/pkg/crypto/unseal"
	"github.com/PumpkinSeed/heimdall/pkg/seal"
	aeadwrapper "github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/helper/salt"
	"github.com/hashicorp/vault/shamir"
	"github.com/hashicorp/vault/vault"
	log "github.com/sirupsen/logrus"
)

const TokenLength = 24

type Request struct {
	SecretShares    int `json:"secret_shares"`
	SecretThreshold int `json:"secret_threshold"`
}

type Result struct {
	SecretShares [][]byte
	RootToken    string
}

var (
	// shamirType is the type for the seal config
	shamirType = "shamir"

	// idPrefix is the prefix used to store tokens for their
	// primary ID based index
	idPrefix = "id/"

	// accessorPrefix is the prefix used to store the index from
	// Accessor to Token ID
	accessorPrefix = "accessor/"

	// parentPrefix is the prefix used to store tokens for their
	// secondary parent based index
	parentPrefix = "parent/"

	// tokenSubPath is the sub-path used for the token store
	// view. This is nested under the system view.
	tokenSubPath = "token/"

	// rolesPrefix is the prefix used to store role information
	rolesPrefix = "roles/"
)

type Init struct {
	unseal *unseal.Unseal

	salts               map[string]*salt.Salt
	baseBarrierView     *vault.BarrierView
	idBarrierView       *vault.BarrierView
	accessorBarrierView *vault.BarrierView
	parentBarrierView   *vault.BarrierView
	rolesBarrierView    *vault.BarrierView

	saltLock   sync.RWMutex
	tokenLocks []*locksutil.LockEntry
}

func NewInit(unseal *unseal.Unseal) *Init {
	view := vault.NewBarrierView(unseal.SecurityBarrier, "sys/"+tokenSubPath)

	return &Init{
		unseal:              unseal,
		salts:               make(map[string]*salt.Salt),
		baseBarrierView:     view,
		idBarrierView:       view.SubView(idPrefix),
		accessorBarrierView: view.SubView(accessorPrefix),
		parentBarrierView:   view.SubView(parentPrefix),
		rolesBarrierView:    view.SubView(rolesPrefix),
		saltLock:            sync.RWMutex{},
		tokenLocks:          locksutil.CreateLocks(),
	}
}

func (init *Init) Initialize(ctx context.Context, req Request) (Result, error) {
	seal := seal.New(init.unseal.Backend, seal.NewSealAccess())
	if err := seal.Init(context.Background()); err != nil {
		return Result{}, err
	}
	barrierKey, _, err := generateShares(req)
	if err != nil {
		return Result{}, err
	}
	sealKey, sealKeyShares, err := generateShares(req)
	if err != nil {
		return Result{}, err
	}
	securityBarrier := unseal.Get().SecurityBarrier
	err = securityBarrier.Initialize(context.Background(), barrierKey, sealKey, rand.Reader)
	if err != nil {
		return Result{}, err
	}

	if err := securityBarrier.Unseal(context.Background(), barrierKey); err != nil {
		return Result{}, err
	}

	defer func(securityBarrier vault.SecurityBarrier) {
		err := securityBarrier.Seal()
		if err != nil {
			log.Println(err)
		}
	}(securityBarrier)

	if err := seal.SetBarrierConfig(context.Background(), &vault.SealConfig{
		Type:            shamirType,
		SecretShares:    req.SecretShares,
		SecretThreshold: req.SecretThreshold,
	}); err != nil {
		return Result{}, err
	}

	if err := seal.GetAccess().Wrapper.(*aeadwrapper.ShamirWrapper).SetAESGCMKeyBytes(sealKey); err != nil {
		return Result{}, err
	}
	if err := seal.SetStoredKeys(ctx, [][]byte{barrierKey}); err != nil {
		return Result{}, fmt.Errorf("failed to store keys: %w", err)
	}

	rootToken, err := init.getRootToken(ctx)
	if err != nil {
		return Result{}, err
	}

	if err := persistMounts(ctx); err != nil {
		return Result{}, err
	}

	return Result{
		SecretShares: sealKeyShares,
		RootToken:    rootToken.ID,
	}, nil
}

func generateShares(req Request) ([]byte, [][]byte, error) {
	masterKey, err := generateKey()
	if err != nil {
		return nil, nil, err
	}

	unSealKeys, err := shamir.Split(masterKey, req.SecretShares, req.SecretThreshold)
	if err != nil {
		return nil, nil, err
	}
	// NOTE encode unseal keys with pgp keys if it's nessecary
	return masterKey, unSealKeys, nil
}

func generateKey() ([]byte, error) {
	buf := make([]byte, 2*aes.BlockSize)
	_, err := rand.Reader.Read(buf)

	return buf, err
}
