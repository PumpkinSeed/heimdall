package transit

import (
	"context"

	"github.com/PumpkinSeed/heimdall/internal/errors"
)

func (t Transit) Backup(ctx context.Context, keyName, engineName string) (string, error) {
	bp, err := t.lm.BackupPolicy(ctx, t.u.Storage(engineName), keyName)
	if err != nil {
		return "", errors.Wrap(err, "transit backup policy execute error ", errors.CodePkgCryptoTransitBackupPolicy)
	}

	return bp, nil
}
