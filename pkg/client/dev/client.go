package dev

import (
	"context"

	"github.com/PumpkinSeed/heimdall/internal/logger"
	"github.com/PumpkinSeed/heimdall/pkg/client"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/transit"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/unseal"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/utils"
	"github.com/PumpkinSeed/heimdall/pkg/healthcheck"
	"github.com/PumpkinSeed/heimdall/pkg/structs"
	"github.com/hashicorp/vault/sdk/physical"
	"github.com/hashicorp/vault/sdk/physical/inmem"
	"github.com/hashicorp/vault/vault"
	log "github.com/sirupsen/logrus"
)

const defaultEngine = "transit/"

type Options struct {
}

func (o Options) Setup() client.Client {
	u := unseal.Get()
	b, sb := buildSecurityBarrier()
	u.SetBackend(b)
	u.SetSecurityBarrier(sb)
	if err := u.DevMode(context.TODO()); err != nil {
		panic(err)
	}

	return &devClient{
		u:       u,
		transit: transit.New(u),
		health:  healthcheck.New(u),
	}
}

func buildSecurityBarrier() (physical.Backend, vault.SecurityBarrier) {
	db, err := inmem.NewInmem(nil, logger.Of(log.StandardLogger()))
	if err != nil {
		panic(err)
	}

	sb, err := vault.NewAESGCMBarrier(db)
	if err != nil {
		panic(err)
	}

	return db, sb
}

type devClient struct {
	u       *unseal.Unseal
	transit transit.Transit
	health  healthcheck.Healthcheck
}

func (d *devClient) CreateKey(ctx context.Context, key *structs.Key) (*structs.KeyResponse, error) {
	err := d.transit.CreateKey(ctx, key.Name, key.Type.String(), defaultEngine)
	return &structs.KeyResponse{
		Status:  utils.GetStatus(err),
		Message: utils.GetMessage(err),
		Key:     key,
	}, err
}

func (d *devClient) ReadKey(ctx context.Context, keyName string) (*structs.KeyResponse, error) {
	key, err := d.transit.GetKey(ctx, keyName, defaultEngine)
	if err != nil {
		log.Errorf("Error with key reading [%s]: %v", keyName, err)

		return nil, err
	}

	return &structs.KeyResponse{
		Status:  utils.GetStatus(err),
		Message: utils.GetMessage(err),
		Key: &structs.Key{
			Name: key.Name,
			Type: structs.EncryptionType(structs.EncryptionType_value[key.Type.String()]),
		},
	}, err
}

func (d *devClient) DeleteKey(ctx context.Context, keyName string) (*structs.KeyResponse, error) {
	err := d.transit.DeleteKey(ctx, keyName, defaultEngine)
	if err != nil {
		log.Errorf("Error with key deletion [%s]: %v", keyName, err)

		return nil, err
	}

	return &structs.KeyResponse{
		Status:  utils.GetStatus(err),
		Message: utils.GetMessage(err),
		Key: &structs.Key{
			Name: keyName,
		},
	}, err
}

func (d *devClient) ListKeys(ctx context.Context) (*structs.KeyListResponse, error) {
	keys, err := d.transit.ListKeys(ctx, defaultEngine)
	if err != nil {
		log.Errorf("Error getting keys: %v", err)
	}

	var keySlice = make([]*structs.Key, 0, len(keys))

	for i := range keys {
		keySlice = append(keySlice, &structs.Key{
			Name: keys[i],
		})
	}

	return &structs.KeyListResponse{
		Status:  utils.GetStatus(err),
		Message: utils.GetMessage(err),
		Keys:    keySlice,
	}, err
}

func (d *devClient) Encrypt(ctx context.Context, encrypt *structs.EncryptRequest) (*structs.CryptoResult, error) {
	e, err := d.transit.Encrypt(ctx, encrypt.KeyName, defaultEngine, transit.BatchRequestItem{
		Plaintext:  encrypt.PlainText,
		Nonce:      encrypt.Nonce,
		KeyVersion: int(encrypt.KeyVersion),
	})
	if err != nil {
		log.Errorf("Error encription [%s]: %v", encrypt.KeyName, err)

		return nil, err
	}

	return &structs.CryptoResult{
		Result: e.Ciphertext,
	}, nil
}

func (d *devClient) Decrypt(ctx context.Context, decrypt *structs.DecryptRequest) (*structs.CryptoResult, error) {
	decRes, err := d.transit.Decrypt(ctx, decrypt.KeyName, defaultEngine, transit.BatchRequestItem{
		Ciphertext: decrypt.Ciphertext,
		Nonce:      decrypt.Nonce,
		KeyVersion: int(decrypt.KeyVersion),
	})
	if err != nil {
		log.Errorf("Error decription [%s]: %v", decrypt.KeyName, err)

		return nil, err
	}

	return &structs.CryptoResult{
		Result: decRes.Plaintext,
	}, err
}

func (d *devClient) Hash(ctx context.Context, hashReq *structs.HashRequest) (*structs.HashResponse, error) {
	hash, err := d.transit.Hash(ctx, hashReq.Input, hashReq.Algorithm, hashReq.Format)
	if err != nil {
		log.Errorf("Error hashing: %v", err)

		return nil, err
	}

	return &structs.HashResponse{
		Result: hash,
	}, err
}

func (d *devClient) GenerateHMAC(ctx context.Context, hmacReq *structs.HMACRequest) (*structs.HMACResponse, error) {
	hmac, err := d.transit.HMAC(ctx, hmacReq.KeyName, hmacReq.Input, hmacReq.Algorithm, int(hmacReq.KeyVersion), defaultEngine)
	if err != nil {
		log.Errorf("Error HMAC generating: %v", err)

		return nil, err
	}

	return &structs.HMACResponse{
		Result: hmac,
	}, err
}

func (d *devClient) Sign(ctx context.Context, req *structs.SignParameters) (*structs.SignResponse, error) {
	req.EngineName = defaultEngine
	signature, err := d.transit.Sign(ctx, req)
	if err != nil {
		log.Errorf("Error generating sign: %v", err)
	}
	return signature, err
}

func (d *devClient) VerifySigned(ctx context.Context, req *structs.VerificationRequest) (*structs.VerificationResponse, error) {
	req.EngineName = defaultEngine
	verificationResult, err := d.transit.VerifySign(ctx, req)
	if err != nil {
		log.Errorf("Error validating signature %v", err)
	}
	return verificationResult, err
}

func (d *devClient) Health(ctx context.Context, req *structs.HealthRequest) (*structs.HealthResponse, error) {
	return d.health.Check(ctx), nil
}
