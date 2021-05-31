package transit

import (
	"context"
	"strings"

	"github.com/PumpkinSeed/heimdall/internal/errors"
)

func (t Transit) Restore(ctx context.Context, keyName, engineName, backup64 string, force bool) error {
	if backup64 == "" {
		return errors.New("'backup' must be supplied", errors.CodePkgCryptoTransitRestoreMissingBackupParam)
	}

	// If a name is given, make sure it does not contain any slashes. The Transit
	// secret engine does not allow sub-paths in key names
	if strings.Contains(keyName, "/") {
		return errors.New("transit restore invalid key format error", errors.CodePkgCryptoTransitRestoreInvalidKeyName)
	}

	if err := t.lm.RestorePolicy(ctx, t.u.Storage(engineName), keyName, backup64, force); err != nil {
		return errors.Wrap(err, "transit restore policy execute error", errors.CodePkgCryptoTransitRestorePolicy)
	}

	return nil
}
