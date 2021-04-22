package seal

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/unseal"
	"github.com/golang/protobuf/proto"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	aeadwrapper "github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/physical"
	"github.com/hashicorp/vault/vault"
	vaultseal "github.com/hashicorp/vault/vault/seal"
	"sync/atomic"
)

func New(physical physical.Backend, access *vaultseal.Access) vault.Seal {
	ret :=  seal{
		physical: physical,
		access:   access,
	}
	ret.config.Store((*vault.SealConfig)(nil))
	return &ret
}

// seal implements tha vault.Seal interface
type seal struct {
	physical physical.Backend
	config atomic.Value
	access *vaultseal.Access
	tokenStore *vault.TokenStore
}

func (s *seal) SetCore(core *vault.Core) {
	panic("implement me")
}

func (s *seal) Init(ctx context.Context) error {
	return nil
}

func (s *seal) Finalize(ctx context.Context) error {
	panic("implement me")
}

func (s *seal) StoredKeysSupported() vaultseal.StoredKeysSupport {
	panic("implement me")
}

func (s *seal) SealWrapable() bool {
	panic("implement me")
}

func (s *seal) SetStoredKeys(ctx context.Context, keys [][]byte) error {
	//writeStoredKeys(ctx, d.core.physical, d.access, keys)

	if keys == nil {
		return fmt.Errorf("keys were nil")
	}
	if len(keys) == 0 {
		return fmt.Errorf("no keys provided")
	}

	buf, err := json.Marshal(keys)
	if err != nil {
		return errwrap.Wrapf("failed to encode keys for storage: {{err}}", err)
	}

	// Encrypt and marshal the keys
	blobInfo, err := s.access.Encrypt(ctx, buf, nil)
	if err != nil {
		return errwrap.Wrapf("failed to encrypt keys for storage: {{err}}", err)
	}

	value, err := proto.Marshal(blobInfo)
	if err != nil {
		return errwrap.Wrapf("failed to marshal value for storage: {{err}}", err)
	}

	// Store the seal configuration.
	pe := &physical.Entry{
		Key:   unseal.BarrierKeysPath,
		Value: value,
	}

	if err := s.physical.Put(ctx, pe); err != nil {
		return errwrap.Wrapf("failed to write keys to storage: {{err}}", err)
	}

	return nil
}

func (s *seal) GetStoredKeys(ctx context.Context) ([][]byte, error) {
	panic("implement me")
}

func (s *seal) BarrierType() string {
	panic("implement me")
}

func (s *seal) BarrierConfig(ctx context.Context) (*vault.SealConfig, error) {
	panic("implement me")
}

func (s *seal) SetBarrierConfig(ctx context.Context, config *vault.SealConfig) error {
	// Provide a way to wipe out the cached value (also prevents actually
	// saving a nil config)
	if config == nil {
		s.config.Store((*vault.SealConfig)(nil))
		return nil
	}

	config.Type = wrapping.Shamir


	// Encode the seal configuration
	buf, err := json.Marshal(config)
	if err != nil {
		return errwrap.Wrapf("failed to encode seal configuration: {{err}}", err)
	}

	// Store the seal configuration
	pe := &physical.Entry{
		Key:   "core/seal-config",
		Value: buf,
	}

	if err := s.physical.Put(ctx, pe); err != nil {
		//d.core.logger.Error("failed to write seal configuration", "error", err)
		return errwrap.Wrapf("failed to write seal configuration: {{err}}", err)
	}

	s.SetCachedBarrierConfig(config.Clone())

	return nil
}

func (s *seal) SetCachedBarrierConfig(config *vault.SealConfig) {
	s.config.Store(config)
}

func (s *seal) RecoveryKeySupported() bool {
	panic("implement me")
}

func (s *seal) RecoveryType() string {
	panic("implement me")
}

func (s *seal) RecoveryConfig(ctx context.Context) (*vault.SealConfig, error) {
	panic("implement me")
}

func (s *seal) RecoveryKey(ctx context.Context) ([]byte, error) {
	panic("implement me")
}

func (s *seal) SetRecoveryConfig(ctx context.Context, config *vault.SealConfig) error {
	panic("implement me")
}

func (s *seal) SetCachedRecoveryConfig(config *vault.SealConfig) {
	panic("implement me")
}

func (s *seal) SetRecoveryKey(ctx context.Context, bytes []byte) error {
	panic("implement me")
}

func (s *seal) VerifyRecoveryKey(ctx context.Context, bytes []byte) error {
	panic("implement me")
}

func (s *seal) GetAccess() *vaultseal.Access {
	return s.access
}

func NewSealAccess() *vaultseal.Access {
	return &vaultseal.Access{
		Wrapper: aeadwrapper.NewShamirWrapper(&wrapping.WrapperOptions{
			Logger: logging.NewVaultLogger(hclog.Debug),
		}),
	}
}

