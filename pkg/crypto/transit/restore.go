package transit

import (
	"context"
	"strings"

	"github.com/PumpkinSeed/heimdall/internal/errors"
)

func (t Transit) Restore(ctx context.Context, keyName, engineName, backup64 string, force bool) error {
	// TODO add error handling
	if backup64 == "" {
		return errors.New("'backup' must be supplied", errors.Code(-1)) // TODO
	}

	// If a name is given, make sure it does not contain any slashes. The Transit
	// secret engine does not allow sub-paths in key names
	if strings.Contains(keyName, "/") {
		return errors.New("", errors.Code(-1)) // TODO
	}

	return t.lm.RestorePolicy(ctx, t.u.Storage(engineName), keyName, backup64, force)
}
