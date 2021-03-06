package init

import (
	"context"
	"crypto/aes"
	"crypto/rand"

	"github.com/PumpkinSeed/heimdall/internal/errors"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/unseal"
	"github.com/PumpkinSeed/heimdall/pkg/seal"
	"github.com/PumpkinSeed/heimdall/pkg/token"
	aeadwrapper "github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	"github.com/hashicorp/vault/shamir"
	"github.com/hashicorp/vault/vault"
	log "github.com/sirupsen/logrus"
)

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
)

type Init struct {
	unseal *unseal.Unseal
	ts     *token.TokenStore
}

func NewInit(unseal *unseal.Unseal) *Init {
	return &Init{
		unseal: unseal,
		ts:     token.NewTokenStore(unseal),
	}
}

func (init *Init) Initialize(ctx context.Context, req Request) (Result, error) {
	seal := seal.New(init.unseal.Backend, seal.NewSealAccess())
	if err := seal.Init(context.Background()); err != nil {
		return Result{}, errors.Wrap(err, "init seal init error", errors.CodePkgInitInitializeSealInit)
	}
	barrierKey, _, err := generateShares(req)
	if err != nil {
		return Result{}, errors.Wrap(err, "init generate shares for barrier key error", errors.CodePkgInitInitializeGenerateSharesBarrier)
	}
	sealKey, sealKeyShares, err := generateShares(req)
	if err != nil {
		return Result{}, errors.Wrap(err, "init generate shares error", errors.CodePkgInitInitializeGenerateSharesSeal)
	}
	securityBarrier := unseal.Get().SecurityBarrier
	err = securityBarrier.Initialize(context.Background(), barrierKey, sealKey, rand.Reader)
	if err != nil {
		return Result{}, errors.Wrap(err, "init security barrier init error", errors.CodePkgInitInitializeSBInit)
	}

	if err := securityBarrier.Unseal(context.Background(), barrierKey); err != nil {
		return Result{}, errors.Wrap(err, "init security barrier unseal error", errors.CodePkgInitInitializeSBUnseal)
	}

	defer func(securityBarrier vault.SecurityBarrier) {
		err := securityBarrier.Seal()
		if err != nil {
			log.Println(errors.Wrap(err, "init security barrier seal error", errors.CodePkgInitInitializeSBSeal))
		}
	}(securityBarrier)

	if err := seal.SetBarrierConfig(context.Background(), &vault.SealConfig{
		Type:            shamirType,
		SecretShares:    req.SecretShares,
		SecretThreshold: req.SecretThreshold,
	}); err != nil {
		return Result{}, errors.Wrap(err, "init seal set barrier config error", errors.CodePkgInitInitializeSealBarrierConfig)
	}

	if err := seal.GetAccess().Wrapper.(*aeadwrapper.ShamirWrapper).SetAESGCMKeyBytes(sealKey); err != nil {
		return Result{}, errors.Wrap(err, "init seal set AES GCM error", errors.CodePkgInitInitializeSealAESGCM)
	}
	if err := seal.SetStoredKeys(ctx, [][]byte{barrierKey}); err != nil {
		return Result{}, errors.Wrap(err, "init failed to store keys", errors.CodePkgInitInitializeSealStoredKeys)
	}

	rootToken, err := init.ts.GenRootToken(ctx, "")
	if err != nil {
		return Result{}, errors.Wrap(err, "init get root token error", errors.CodePkgInitGetRootToken)
	}

	if err := persistMounts(ctx); err != nil {
		return Result{}, errors.Wrap(err, "init persist mounts error", errors.CodePkgInitPersistMounts)
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
