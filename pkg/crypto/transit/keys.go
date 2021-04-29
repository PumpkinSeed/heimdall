package transit

import (
	"context"
	"crypto/rand"
	"errors"

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
		return err
	}
	if policy == nil {
		return errors.New("error generating key: returned policy was nil")
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
		return nil, err
	}
	if p == nil {
		return nil, err
	}

	defer p.Unlock()

	return p, nil
}

func (t Transit) ListKeys(ctx context.Context, engineName string) ([]string, error) {
	if !t.u.Status().Unsealed {
		return nil, unseal.ErrSealed
	}
	return t.u.Storage(engineName).List(ctx, "policy/")
}

func (t Transit) DeleteKey(ctx context.Context, name, engineName string) error {
	if !t.u.Status().Unsealed {
		return unseal.ErrSealed
	}
	return t.lm.DeletePolicy(ctx, t.u.Storage(engineName), name)
}

func getKeyType(typ string) keysutil.KeyType {
	if v, ok := structs.EncryptionType_value[typ]; ok {
		return keysutil.KeyType(v)
	}
	return keysutil.KeyType_AES256_GCM96
}
