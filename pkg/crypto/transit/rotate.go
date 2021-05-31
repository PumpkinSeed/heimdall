package transit

import (
	"context"
	"crypto/rand"

	"github.com/PumpkinSeed/heimdall/internal/errors"
)

func (t Transit) Rotate(ctx context.Context, keyName, engineName string) error {
	p, err := t.GetKey(ctx, keyName, engineName)
	if err != nil {
		return errors.Wrap(err, "transit rotate get key error", errors.CodePkgCryptoTransitRotateGetKey)
	}

	if err := p.Rotate(ctx, t.u.Storage(engineName), rand.Reader); err != nil {
		return errors.Wrap(err, "transit rotate error", errors.CodePkgCryptoTransitRotateRotate)
	}
	return nil
}
