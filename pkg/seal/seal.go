package seal

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/unseal"
	"github.com/golang/protobuf/proto"
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
	ret := seal{
		physical: physical,
		access:   access,
	}
	ret.config.Store((*vault.SealConfig)(nil))
	return &ret
}

// seal implements tha vault.Seal interface
type seal struct {
	physical   physical.Backend
	config     atomic.Value
	access     *vaultseal.Access
	tokenStore *vault.TokenStore
}

func (s *seal) SetCore(core *vault.Core) {}

func (s *seal) Init(ctx context.Context) error {
	return nil
}

func (s *seal) Finalize(ctx context.Context) error {
	return nil
}

func (s *seal) StoredKeysSupported() vaultseal.StoredKeysSupport {
	return 0
}

func (s *seal) SealWrapable() bool {
	return false
}

func (s *seal) SetStoredKeys(ctx context.Context, keys [][]byte) error {
	if keys == nil {
		return fmt.Errorf("keys were nil")
	}
	if len(keys) == 0 {
		return fmt.Errorf("no keys provided")
	}

	buf, err := json.Marshal(keys)
	if err != nil {
		return fmt.Errorf("failed to encode keys for storage: %v", err)
	}

	// Encrypt and marshal the keys
	blobInfo, err := s.access.Encrypt(ctx, buf, nil)
	if err != nil {
		return fmt.Errorf("failed to encrypt keys for storage: %v", err)
	}

	value, err := proto.Marshal(blobInfo)
	if err != nil {
		return fmt.Errorf("failed to marshal value for storage: %v", err)
	}

	// Store the seal configuration.
	pe := &physical.Entry{
		Key:   unseal.BarrierKeysPath,
		Value: value,
	}

	if err := s.physical.Put(ctx, pe); err != nil {
		return fmt.Errorf("failed to write keys to storage: %v", err)
	}

	return nil
}

func (s *seal) GetStoredKeys(ctx context.Context) ([][]byte, error) {
	return nil, nil
}

func (s *seal) BarrierType() string {
	return ""
}

func (s *seal) BarrierConfig(ctx context.Context) (*vault.SealConfig, error) {
	return nil, nil
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
		return fmt.Errorf("failed to encode seal configuration: %v", err)
	}

	// Store the seal configuration
	pe := &physical.Entry{
		Key:   "core/seal-config",
		Value: buf,
	}

	if err := s.physical.Put(ctx, pe); err != nil {
		return fmt.Errorf("failed to write seal configuration: %v", err)
	}

	s.SetCachedBarrierConfig(config.Clone())

	return nil
}

func (s *seal) SetCachedBarrierConfig(config *vault.SealConfig) {
	s.config.Store(config)
}

func (s *seal) RecoveryKeySupported() bool {
	return false
}

func (s *seal) RecoveryType() string {
	return ""
}

func (s *seal) RecoveryConfig(ctx context.Context) (*vault.SealConfig, error) {
	return nil, nil
}

func (s *seal) RecoveryKey(ctx context.Context) ([]byte, error) {
	return nil, nil
}

func (s *seal) SetRecoveryConfig(ctx context.Context, config *vault.SealConfig) error {
	return nil
}

func (s *seal) SetCachedRecoveryConfig(config *vault.SealConfig) {}

func (s *seal) SetRecoveryKey(ctx context.Context, bytes []byte) error {
	return nil
}

func (s *seal) VerifyRecoveryKey(ctx context.Context, bytes []byte) error {
	return nil
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
