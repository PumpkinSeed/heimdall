package transit

import (
	"github.com/PumpkinSeed/heimdall/pkg/crypto/unseal"
	"github.com/emvi/null"
	"github.com/hashicorp/vault/sdk/helper/keysutil"
)

type Transit struct {
	lm *keysutil.LockManager
	u  *unseal.Unseal
}

func New(u *unseal.Unseal) Transit {
	lm, err := keysutil.NewLockManager(false, 0)
	if err != nil {
		panic(err)
	}

	return Transit{
		lm: lm,
		u:  u,
	}
}

func (t Transit) CheckEngine(engineName string) (bool, error) {
	return t.u.CheckEngine(engineName)
}

// BatchRequestItem represents a request item for batch processing
type BatchRequestItem struct {
	// Context for key derivation. This is required for derived keys.
	Context string `json:"context" structs:"context" mapstructure:"context"`

	// DecodedContext is the base64 decoded version of Context
	DecodedContext []byte

	// Plaintext for encryption
	Plaintext string `json:"plaintext" structs:"plaintext" mapstructure:"plaintext"`

	// Ciphertext for decryption
	Ciphertext string `json:"ciphertext" structs:"ciphertext" mapstructure:"ciphertext"`

	// Nonce to be used when v1 convergent encryption is used
	Nonce string `json:"nonce" structs:"nonce" mapstructure:"nonce"`

	// The key version to be used for encryption
	KeyVersion int `json:"key_version" structs:"key_version" mapstructure:"key_version"`

	// DecodedNonce is the base64 decoded version of Nonce
	DecodedNonce []byte
}

// EncryptBatchResponseItem represents a response item for batch processing
type EncryptBatchResponseItem struct {
	// Ciphertext for the plaintext present in the corresponding batch
	// request item
	Ciphertext string `json:"ciphertext,omitempty" structs:"ciphertext" mapstructure:"ciphertext"`

	// KeyVersion defines the key version used to encrypt plaintext.
	KeyVersion int `json:"key_version,omitempty" structs:"key_version" mapstructure:"key_version"`
}

type DecryptBatchResponseItem struct {
	// Plaintext for the ciphertext present in the corresponding batch
	// request item
	Plaintext string `json:"plaintext" structs:"plaintext" mapstructure:"plaintext"`
}

type KeyConfiguration struct {
	// MinDecryptionVersion if set, the minimum version of the key allowed to be decrypted.
	// For signing keys, the minimum version allowed to be used for verification.
	MinDecryptionVersion null.Int64 `json:"min_decryption_version"`
	// MinEncryptionVersion if set, the minimum version of the key allowed to be used for encryption;
	// or for signing keys, to be used for signing.
	// If set to zero, only the latest version of the key is allowed.
	MinEncryptionVersion null.Int64 `json:"min_encryption_version"`
	// DeletionAllowed whether to allow deletion of the key
	DeletionAllowed null.Bool `json:"deletion_allowed"`
	// Exportable enables export of the key. Once set, this cannot be disabled.
	Exportable null.Bool `json:"exportable"`
	// AllowPlaintextBackup Enables taking a backup of the named key in plaintext format.
	// Once set, this cannot be disabled.
	AllowPlaintextBackup null.Bool `json:"allow_plaintext_backup"`
}
