package transit

import (
	"context"
	"crypto/rand"
)

func (t Transit) Rotate(ctx context.Context, keyName, engineName string) error {
	// TODO add error handling
	p, err := t.GetKey(ctx, keyName, engineName)
	if err != nil {
		return err
	}

	return p.Rotate(ctx, t.u.Storage(engineName), rand.Reader)
}
