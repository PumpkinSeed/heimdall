package dev

import (
	"context"
	"encoding/json"

	"github.com/PumpkinSeed/heimdall/internal/errors"
	"github.com/PumpkinSeed/heimdall/internal/logger"
	"github.com/PumpkinSeed/heimdall/pkg/client"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/transit"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/unseal"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/utils"
	"github.com/PumpkinSeed/heimdall/pkg/healthcheck"
	"github.com/PumpkinSeed/heimdall/pkg/structs"
	"github.com/emvi/null"
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
	b, sb, err := buildSecurityBarrier()
	if err != nil {
		log.Error(errors.Wrap(err, "dev client setup security barrier error", errors.CodeClientDevSetup))
		return nil
	}
	u.SetBackend(b)
	u.SetSecurityBarrier(sb)
	if err := u.DevMode(context.TODO()); err != nil {
		log.Error(errors.Wrap(err, "dev client setup dev mode startup error", errors.CodeClientDevSetup))
		return nil
	}

	return &devClient{
		u:       u,
		transit: transit.New(u),
		health:  healthcheck.New(u),
	}
}

func buildSecurityBarrier() (physical.Backend, vault.SecurityBarrier, error) {
	db, err := inmem.NewInmem(nil, logger.Of(log.StandardLogger()))
	if err != nil {
		return nil, nil, errors.Wrap(err, "dev client physical database init error", errors.CodeClientDevSetupBarrierPhysical)
	}

	sb, err := vault.NewAESGCMBarrier(db)
	if err != nil {
		return nil, nil, errors.Wrap(err, "dev client AES GCM init error", errors.CodeClientDevSetupBarrierLogical)
	}

	return db, sb, nil
}

type devClient struct {
	u       *unseal.Unseal
	transit transit.Transit
	health  healthcheck.Healthcheck
}

func (d *devClient) CreateKey(ctx context.Context, key *structs.Key) (*structs.KeyResponse, error) {
	err := d.transit.CreateKey(ctx, key.Name, key.Type.String(), defaultEngine)
	if err != nil {
		return nil, errors.Wrap(err, "dev client create key error", errors.CodeClientDevCreateKey)
	}
	return &structs.KeyResponse{
		Status:  utils.GetStatus(err),
		Message: utils.GetMessage(err),
		Key:     key,
	}, nil
}

func (d *devClient) ReadKey(ctx context.Context, keyName string) (*structs.KeyResponse, error) {
	key, err := d.transit.GetKey(ctx, keyName, defaultEngine)
	if err != nil {
		log.Debugf("Error with key reading [%s]: %v", keyName, err)

		return nil, errors.Wrap(err, "dev client read key error", errors.CodeClientDevReadKey)
	}

	return &structs.KeyResponse{
		Status:  utils.GetStatus(err),
		Message: utils.GetMessage(err),
		Key: &structs.Key{
			Name: key.Name,
			Type: structs.EncryptionType(structs.EncryptionType_value[key.Type.String()]),
		},
	}, nil
}

func (d *devClient) DeleteKey(ctx context.Context, keyName string) (*structs.KeyResponse, error) {
	err := d.transit.DeleteKey(ctx, keyName, defaultEngine)
	if err != nil {
		log.Debugf("Error with key deletion [%s]: %v", keyName, err)

		return nil, errors.Wrap(err, "dev client delete key error", errors.CodeClientDevDeleteKey)
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

		return nil, errors.Wrap(err, "dev client list keys error", errors.CodeClientDevListKeys)
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
		log.Debugf("Error encription [%s]: %v", encrypt.KeyName, err)

		return nil, errors.Wrap(err, "dev client encrypt error", errors.CodeClientDevEncrypt)
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
		log.Debugf("Error decription [%s]: %v", decrypt.KeyName, err)

		return nil, errors.Wrap(err, "dev client decrypt error", errors.CodeClientDevDecrypt)
	}

	return &structs.CryptoResult{
		Result: decRes.Plaintext,
	}, err
}

func (d *devClient) Hash(ctx context.Context, hashReq *structs.HashRequest) (*structs.HashResponse, error) {
	hash, err := d.transit.Hash(ctx, hashReq.Input, hashReq.Algorithm, hashReq.Format)
	if err != nil {
		log.Debugf("Error hashing: %v", err)

		return nil, errors.Wrap(err, "dev client hash error", errors.CodeClientDevHash)
	}

	return &structs.HashResponse{
		Result: hash,
	}, err
}

func (d *devClient) GenerateHMAC(ctx context.Context, hmacReq *structs.HMACRequest) (*structs.HMACResponse, error) {
	hmac, err := d.transit.HMAC(ctx, hmacReq.KeyName, hmacReq.Input, hmacReq.Algorithm, int(hmacReq.KeyVersion), defaultEngine)
	if err != nil {
		log.Debugf("Error HMAC generating: %v", err)

		return nil, errors.Wrap(err, "dev client hmac error", errors.CodeClientDevHmac)
	}

	return &structs.HMACResponse{
		Result: hmac,
	}, err
}

func (d *devClient) Sign(ctx context.Context, req *structs.SignParameters) (*structs.SignResponse, error) {
	signature, err := d.transit.Sign(ctx, req, defaultEngine)
	if err != nil {
		log.Debugf("Error generating sign: %v", err)

		return nil, errors.Wrap(err, "dev client sign error", errors.CodeClientDevSign)
	}

	return signature, nil
}

func (d *devClient) VerifySigned(ctx context.Context, req *structs.VerificationRequest) (*structs.VerificationResponse, error) {
	verificationResult, err := d.transit.VerifySign(ctx, req, defaultEngine)
	if err != nil {
		log.Debugf("Error validating signature %v", err)

		return nil, errors.Wrap(err, "dev client sign error", errors.CodeClientDevVerifySign)
	}
	return verificationResult, err
}

func (d *devClient) Rewrap(ctx context.Context, in *structs.RewrapRequest) (*structs.CryptoResult, error) {
	rewrap, err := d.transit.Rewrap(ctx, in.KeyName, defaultEngine, transit.BatchRequestItem{
		Context:    in.Context,
		Plaintext:  in.PlainText,
		Nonce:      in.Nonce,
		KeyVersion: int(in.KeyVersion),
	})
	if err != nil {
		log.Debugf("Error rewrapping key %v", err)

		return nil, errors.Wrap(err, "dev client rewrap error", errors.CodeClientDevRewrap)
	}
	return &structs.CryptoResult{
		Result: rewrap.Ciphertext,
	}, nil
}

func (d *devClient) UpdateKeyConfiguration(ctx context.Context, in *structs.KeyConfig) (*structs.Empty, error) {
	err := d.transit.UpdateKeyConfiguration(ctx, in.KeyName, defaultEngine, transit.KeyConfiguration{
		MinDecryptionVersion: utils.NullInt64FromPtr(in.MinDecryptionVersion),
		MinEncryptionVersion: utils.NullInt64FromPtr(in.MinEncryptionVersion),
		DeletionAllowed:      utils.NullBoolFromPtr(in.DeletionAllowed),
		Exportable:           utils.NullBoolFromPtr(in.Exportable),
		AllowPlaintextBackup: utils.NullBoolFromPtr(in.AllowPlaintextBackup),
	})
	if err != nil {
		log.Debugf("Error update key config %v", err)

		return nil, errors.Wrap(err, "dev client update key config error", errors.CodeClientDevUpdateKeyConfig)
	}
	return &structs.Empty{}, nil
}

func (d *devClient) RotateKey(ctx context.Context, in *structs.RotateRequest) (*structs.Empty, error) {
	err := d.transit.Rotate(ctx, in.KeyName, defaultEngine)
	if err != nil {
		log.Debugf("Error rotate key %v", err)

		return nil, errors.Wrap(err, "dev client rotate key error", errors.CodeClientDevRotate)
	}
	return &structs.Empty{}, nil
}

func (d *devClient) ExportKey(ctx context.Context, in *structs.ExportRequest) (*structs.ExportResult, error) {
	export, err := d.transit.Export(ctx, in.KeyName, defaultEngine, in.ExportType, in.Version)
	if err != nil {
		log.Debugf("Error export key %v", err)

		return nil, errors.Wrap(err, "dev client export key error", errors.CodeClientDevExport)
	}

	result, err := json.Marshal(export)
	if err != nil {
		log.Debugf("Error export key result marshal %v", err)

		return nil, errors.Wrap(err, "dev client export key result marshal error", errors.CodeClientDevExport)
	}

	return &structs.ExportResult{
		Result: string(result),
	}, nil
}

func (d *devClient) BackupKey(ctx context.Context, in *structs.BackupRequest) (*structs.BackupResult, error) {
	backup, err := d.transit.Backup(ctx, in.KeyName, defaultEngine)
	if err != nil {
		log.Debugf("Error backup key %v", err)

		return nil, errors.Wrap(err, "dev client backup key error", errors.CodeClientDevBackup)
	}

	return &structs.BackupResult{
		Result: backup,
	}, nil
}

func (d *devClient) RestoreKey(ctx context.Context, in *structs.RestoreRequest) (*structs.Empty, error) {
	err := d.transit.Restore(ctx, in.KeyName, defaultEngine, in.Backup64, in.Force)
	if err != nil {
		log.Debugf("Error restore key %v", err)

		return nil, errors.Wrap(err, "dev client restore key error", errors.CodeClientDevRestore)
	}

	return &structs.Empty{}, nil
}

func (d *devClient) GenerateKey(ctx context.Context, in *structs.GenerateKeyRequest) (*structs.GenerateKeyResponse, error) {
	result, err := d.transit.GenerateKey(ctx, defaultEngine, transit.GenerateRequest{
		Name:       in.Name,
		Plaintext:  in.Plaintext,
		Context:    null.NewString(in.Context, true),
		Nonce:      null.NewString(in.Nonce, true),
		Bits:       null.NewInt64(in.Bits, true),
		KeyVersion: null.NewInt64(in.KeyVersion, true),
	})
	if err != nil {
		log.Debugf("Error generate key %v", err)

		return nil, errors.Wrap(err, "dev client generate key error", errors.CodeClientDevGenerateKey)
	}

	return &structs.GenerateKeyResponse{
		Ciphertext: result.Ciphertext,
		KeyVersion: result.KeyVersion,
		Plaintext:  result.Plaintext,
	}, nil
}

func (d *devClient) GenerateRandomBytes(ctx context.Context, in *structs.GenerateBytesRequest) (*structs.GenerateBytesResponse, error) {
	result, err := d.transit.GenerateRandomBytes(ctx, in.UrlBytes, in.Format, int(in.BytesCount))
	if err != nil {
		log.Debugf("Error generate key %v", err)

		return nil, errors.Wrap(err, "dev client generate key error", errors.CodeClientDevGenerateRandomBytes)
	}

	return &structs.GenerateBytesResponse{
		Result: result,
	}, nil
}

func (d *devClient) Health(ctx context.Context, req *structs.HealthRequest) (*structs.HealthResponse, error) {
	return d.health.Check(ctx), nil
}
