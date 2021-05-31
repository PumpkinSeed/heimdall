package client

import (
	"context"

	"github.com/PumpkinSeed/heimdall/pkg/structs"
)

type Options interface {
	Setup() Client
}

func New(o Options) Client {
	return o.Setup()
}

type Client interface {
	CreateKey(ctx context.Context, key *structs.Key) (*structs.KeyResponse, error)
	ReadKey(ctx context.Context, keyName string) (*structs.KeyResponse, error)
	DeleteKey(ctx context.Context, keyName string) (*structs.KeyResponse, error)
	ListKeys(ctx context.Context) (*structs.KeyListResponse, error)
	Encrypt(ctx context.Context, encrypt *structs.EncryptRequest) (*structs.CryptoResult, error)
	Decrypt(ctx context.Context, decrypt *structs.DecryptRequest) (*structs.CryptoResult, error)
	Hash(ctx context.Context, hash *structs.HashRequest) (*structs.HashResponse, error)
	GenerateHMAC(ctx context.Context, hmac *structs.HMACRequest) (*structs.HMACResponse, error)
	Sign(ctx context.Context, in *structs.SignParameters) (*structs.SignResponse, error)
	VerifySigned(ctx context.Context, in *structs.VerificationRequest) (*structs.VerificationResponse, error)
	Rewrap(ctx context.Context, in *structs.RewrapRequest) (*structs.CryptoResult, error)
	UpdateKeyConfiguration(ctx context.Context, in *structs.KeyConfig) (*structs.Empty, error)
	RotateKey(ctx context.Context, in *structs.RotateRequest) (*structs.Empty, error)
	ExportKey(ctx context.Context, in *structs.ExportRequest) (*structs.ExportResult, error)
	BackupKey(ctx context.Context, in *structs.BackupRequest) (*structs.BackupResult, error)
	RestoreKey(ctx context.Context, in *structs.RestoreRequest) (*structs.Empty, error)
	GenerateKey(ctx context.Context, in *structs.GenerateKeyRequest) (*structs.GenerateKeyResponse, error)
	GenerateRandomBytes(ctx context.Context, in *structs.GenerateBytesRequest) (*structs.GenerateBytesResponse, error)
	Health(ctx context.Context, in *structs.HealthRequest) (*structs.HealthResponse, error)
}
