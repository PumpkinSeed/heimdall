package transit

import (
	"context"
	"crypto/rand"
	"errors"

	"github.com/hashicorp/vault/sdk/helper/keysutil"
	"github.com/sirupsen/logrus"
)

func (t Transit) CreateKey(ctx context.Context, name, keyType string) error {
	polReq := keysutil.PolicyRequest{
		Upsert:               true,
		Storage:              t.storage,
		Name:                 name,
		Derived:              false,
		Convergent:           false,
		Exportable:           false,
		AllowPlaintextBackup: false,
		KeyType:              getKeyType(keyType),
	}

	policy, upserted, err := t.lm.GetPolicy(ctx, polReq, rand.Reader)
	if err != nil {
		return err
	}
	if policy == nil {
		return errors.New("error generating key: returned policy was nil")
	}
	if !upserted {
		logrus.Warnf("key %s already existed", name)
	}

	return nil
}

func (t Transit) GetKey(ctx context.Context, name string) (*keysutil.Policy, error) {
	p, _, err := t.lm.GetPolicy(ctx, keysutil.PolicyRequest{
		Storage: t.storage,
		Name:    name,
	}, rand.Reader)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, err
	}

	defer p.Unlock()

	return p, nil
}

func (t Transit) DeleteKey(ctx context.Context, name string) error {
	return t.lm.DeletePolicy(ctx, t.storage, name)
}

func getKeyType(typ string) keysutil.KeyType {
	switch typ {
	case "aes128-gcm96":
		return keysutil.KeyType_AES128_GCM96
	case "aes256-gcm96":
		return keysutil.KeyType_AES256_GCM96
	case "chacha20-poly1305":
		return keysutil.KeyType_ChaCha20_Poly1305
	case "ecdsa-p256":
		return keysutil.KeyType_ECDSA_P256
	case "ecdsa-p384":
		return keysutil.KeyType_ECDSA_P384
	case "ecdsa-p521":
		return keysutil.KeyType_ECDSA_P521
	case "ed25519":
		return keysutil.KeyType_ED25519
	case "rsa-2048":
		return keysutil.KeyType_RSA2048
	case "rsa-3072":
		return keysutil.KeyType_RSA3072
	case "rsa-4096":
		return keysutil.KeyType_RSA4096
	default:
		return keysutil.KeyType_AES256_GCM96
	}
}
