package init

import (
	"context"
	"crypto/aes"
	"crypto/rand"
	"fmt"

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

	rootToken, err := init.ts.GenRootToken(ctx, "")
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
