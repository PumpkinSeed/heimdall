package transit

import (
	"context"
	"crypto/rand"

	"github.com/PumpkinSeed/heimdall/internal/errors"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/unseal"
	"github.com/PumpkinSeed/heimdall/pkg/structs"
	"github.com/hashicorp/vault/sdk/helper/keysutil"
	"github.com/sirupsen/logrus"
)

func (t Transit) CreateKey(ctx context.Context, name, keyType, engineName string) error {
	if !t.u.Status().Unsealed {
		return unseal.ErrSealed
	}
	polReq := keysutil.PolicyRequest{
		Upsert:               true,
		Storage:              t.u.Storage(engineName),
		Name:                 name,
		Derived:              false,
		Convergent:           false,
		Exportable:           false,
		AllowPlaintextBackup: false,
		KeyType:              getKeyType(keyType),
	}

	policy, upserted, err := t.lm.GetPolicy(ctx, polReq, rand.Reader)
	if err != nil {
		return errors.Wrap(err, "transit create key get policy error", errors.CodePkgCryptoTransitCreateKey)
	}
	if policy == nil {
		return errors.New("transit error generating key: returned policy was nil", errors.CodePkgCryptoTransitCreateKey)
	}
	defer policy.Unlock()
	if !upserted {
		logrus.Warnf("key %s already existed", name)
	}

	return nil
}

func (t Transit) GetKey(ctx context.Context, name, engineName string) (*keysutil.Policy, error) {
	if !t.u.Status().Unsealed {
		return nil, unseal.ErrSealed
	}
	p, _, err := t.lm.GetPolicy(ctx, keysutil.PolicyRequest{
		Storage: t.u.Storage(engineName),
		Name:    name,
	}, rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "transit get key get policy error", errors.CodePkgCryptoTransitGetKey)
	}
	if p == nil {
		return nil, errors.New("transit get key policy not found", errors.CodePkgCryptoTransitGetKeyNotFound)
	}

	defer p.Unlock()

	return p, nil
}

func (t Transit) ListKeys(ctx context.Context, engineName string) ([]string, error) {
	if !t.u.Status().Unsealed {
		return nil, unseal.ErrSealed
	}
	list, err := t.u.Storage(engineName).List(ctx, "policy/")
	if err != nil {
		return nil, errors.Wrap(err, "transit list keys error", errors.CodePkgCryptoTransitListKeys)
	}
	return list, nil
}

func (t Transit) DeleteKey(ctx context.Context, name, engineName string) error {
	if !t.u.Status().Unsealed {
		return unseal.ErrSealed
	}
	err := t.lm.DeletePolicy(ctx, t.u.Storage(engineName), name)
	if err != nil {
		return errors.Wrap(err, "transit delete key error", errors.CodePkgCryptoTransitDeleteKey)
	}
	return err
}

func (t Transit) UpdateKeyConfiguration(ctx context.Context, name, engineName string, config KeyConfiguration) error {
	p, err := t.GetKey(ctx, name, engineName)
	if err != nil {
		return errors.Wrap(err, "transit update key config get key error", errors.CodePkgCryptoTransitUpdateKeyConfigGetKey)
	}

	persistNeeded := false

	if config.MinDecryptionVersion.Valid {
		minDecryptionVersion := config.MinDecryptionVersion.Int64

		if minDecryptionVersion < 0 {
			return errors.New("min decryption version cannot be negative", errors.CodePkgCryptoTransitUpdateKeyConfigMinDecryptVersionNegative)
		}

		if minDecryptionVersion == 0 {
			minDecryptionVersion = 1
			logrus.Warn("since Vault 0.3, transit key numbering starts at 1; forcing minimum to 1")
		}

		if minDecryptionVersion != int64(p.MinDecryptionVersion) {
			if minDecryptionVersion > int64(p.LatestVersion) {
				return errors.Newf(errors.CodePkgCryptoTransitUpdateKeyConfigMinDecryptVersionLatest,
					"cannot set min decryption version of %d, latest key version is %d",
					minDecryptionVersion, p.LatestVersion)
			}
			p.MinDecryptionVersion = int(minDecryptionVersion)
			persistNeeded = true
		}
	}

	if config.MinEncryptionVersion.Valid {
		minEncryptionVersion := config.MinEncryptionVersion.Int64

		if minEncryptionVersion < 0 {
			return errors.New("min encryption version cannot be negative", errors.CodePkgCryptoTransitUpdateKeyConfigMinEncryptVersionNegative)
		}

		if minEncryptionVersion != int64(p.MinEncryptionVersion) {
			if minEncryptionVersion > int64(p.LatestVersion) {
				return errors.Newf(errors.CodePkgCryptoTransitUpdateKeyConfigMinEncryptVersionLatest,
					"cannot set min encryption version of %d, latest key version is %d",
					minEncryptionVersion, p.LatestVersion)
			}
			p.MinEncryptionVersion = int(minEncryptionVersion)
			persistNeeded = true
		}
	}

	// Check here to get the final picture after the logic on each
	// individually. MinDecryptionVersion will always be 1 or above.
	if p.MinEncryptionVersion > 0 &&
		p.MinEncryptionVersion < p.MinDecryptionVersion {
		return errors.Newf(errors.CodePkgCryptoTransitUpdateKeyConfigMinEncryptMinDecrypt,
			"cannot set min encryption/decryption values; min encryption version of %d must be greater than or equal to min decryption version of %d",
			p.MinEncryptionVersion, p.MinDecryptionVersion)
	}

	if config.DeletionAllowed.Valid {
		allowDeletion := config.DeletionAllowed.Bool
		if allowDeletion != p.DeletionAllowed {
			p.DeletionAllowed = allowDeletion
			persistNeeded = true
		}
	}

	// Add this as a guard here before persisting since we now require the min
	// decryption version to start at 1; even if it's not explicitly set here,
	// force the upgrade
	if p.MinDecryptionVersion == 0 {
		p.MinDecryptionVersion = 1
		persistNeeded = true
	}

	if config.Exportable.Valid {
		exportable := config.Exportable.Bool
		// Don't unset the already set value
		if exportable && !p.Exportable {
			p.Exportable = exportable
			persistNeeded = true
		}
	}

	if config.AllowPlaintextBackup.Valid {
		allowPlaintextBackup := config.AllowPlaintextBackup.Bool
		// Don't unset the already set value
		if allowPlaintextBackup && !p.AllowPlaintextBackup {
			p.AllowPlaintextBackup = allowPlaintextBackup
			persistNeeded = true
		}
	}

	if !persistNeeded {
		return nil
	}

	switch {
	case p.MinAvailableVersion > p.MinEncryptionVersion:
		return errors.New("min encryption version should not be less than min available version",
			errors.CodePkgCryptoTransitUpdateKeyConfigMinEncryptMinAvailable)
	case p.MinAvailableVersion > p.MinDecryptionVersion:
		return errors.New("min decryption version should not be less then min available version",
			errors.CodePkgCryptoTransitUpdateKeyConfigMinDecryptMinAvailable)
	}

	return errors.Wrap(p.Persist(ctx, t.u.Storage(engineName)), "error persisting key update",
		errors.CodePkgCryptoTransitUpdateKeyConfigPersist)
}

func getKeyType(typ string) keysutil.KeyType {
	if v, ok := structs.EncryptionType_value[typ]; ok {
		return keysutil.KeyType(v)
	}
	return keysutil.KeyType_AES256_GCM96
}
