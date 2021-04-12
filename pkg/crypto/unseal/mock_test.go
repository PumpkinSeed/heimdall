package unseal

import (
	"context"
	"io"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/physical"
	"github.com/hashicorp/vault/vault"
	"github.com/stretchr/testify/mock"
)

type mockBackend struct {
	mock.Mock
}

func (m mockBackend) Put(ctx context.Context, entry *physical.Entry) error {
	panic("implement me")
}

func (m mockBackend) Get(ctx context.Context, key string) (*physical.Entry, error) {
	args := m.Called(ctx, key)
	return args.Get(0).(*physical.Entry), args.Error(1)
}

func (m mockBackend) Delete(ctx context.Context, key string) error {
	panic("implement me")
}

func (m mockBackend) List(ctx context.Context, prefix string) ([]string, error) {
	panic("implement me")
}

type mockSecurityBarrier struct {
	mock.Mock
	backend physical.Backend
}

func (m mockSecurityBarrier) Initialized(ctx context.Context) (bool, error) {
	return true, nil
}

func (m mockSecurityBarrier) Initialize(ctx context.Context, masterKey []byte, sealKey []byte, random io.Reader) error {
	return nil
}

func (m mockSecurityBarrier) GenerateKey(reader io.Reader) ([]byte, error) {
	panic("implement me")
}

func (m mockSecurityBarrier) KeyLength() (int, int) {
	panic("implement me")
}

func (m mockSecurityBarrier) Sealed() (bool, error) {
	panic("implement me")
}

func (m mockSecurityBarrier) Unseal(ctx context.Context, key []byte) error {
	return nil
}

func (m mockSecurityBarrier) VerifyMaster(key []byte) error {
	panic("implement me")
}

func (m mockSecurityBarrier) SetMasterKey(key []byte) error {
	panic("implement me")
}

func (m mockSecurityBarrier) ReloadKeyring(ctx context.Context) error {
	panic("implement me")
}

func (m mockSecurityBarrier) ReloadMasterKey(ctx context.Context) error {
	panic("implement me")
}

func (m mockSecurityBarrier) Seal() error {
	panic("implement me")
}

func (m mockSecurityBarrier) Rotate(ctx context.Context, reader io.Reader) (uint32, error) {
	panic("implement me")
}

func (m mockSecurityBarrier) CreateUpgrade(ctx context.Context, term uint32) error {
	panic("implement me")
}

func (m mockSecurityBarrier) DestroyUpgrade(ctx context.Context, term uint32) error {
	panic("implement me")
}

func (m mockSecurityBarrier) CheckUpgrade(ctx context.Context) (bool, uint32, error) {
	panic("implement me")
}

func (m mockSecurityBarrier) ActiveKeyInfo() (*vault.KeyInfo, error) {
	panic("implement me")
}

func (m mockSecurityBarrier) RotationConfig() (vault.KeyRotationConfig, error) {
	panic("implement me")
}

func (m mockSecurityBarrier) SetRotationConfig(ctx context.Context, config vault.KeyRotationConfig) error {
	panic("implement me")
}

func (m mockSecurityBarrier) Rekey(ctx context.Context, bytes []byte) error {
	panic("implement me")
}

func (m mockSecurityBarrier) Keyring() (*vault.Keyring, error) {
	panic("implement me")
}

func (m mockSecurityBarrier) ConsumeEncryptionCount(consumer func(int64) error) error {
	panic("implement me")
}

func (m mockSecurityBarrier) AddRemoteEncryptions(encryptions int64) {
	panic("implement me")
}

func (m mockSecurityBarrier) CheckBarrierAutoRotate(ctx context.Context) (string, error) {
	panic("implement me")
}

func (m mockSecurityBarrier) List(ctx context.Context, s string) ([]string, error) {
	panic("implement me")
}

func (m mockSecurityBarrier) Get(ctx context.Context, s string) (*logical.StorageEntry, error) {
	get, err := m.backend.Get(ctx, s)
	if err != nil {
		return nil, err
	}
	return &logical.StorageEntry{
		Key:      get.Key,
		Value:    get.Value,
		SealWrap: get.SealWrap,
	}, nil
}

func (m mockSecurityBarrier) Put(ctx context.Context, entry *logical.StorageEntry) error {
	panic("implement me")
}

func (m mockSecurityBarrier) Delete(ctx context.Context, s string) error {
	panic("implement me")
}

func (m mockSecurityBarrier) Encrypt(ctx context.Context, key string, plaintext []byte) ([]byte, error) {
	panic("implement me")
}

func (m mockSecurityBarrier) Decrypt(ctx context.Context, key string, ciphertext []byte) ([]byte, error) {
	panic("implement me")
}
