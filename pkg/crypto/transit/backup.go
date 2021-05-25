package transit

import "context"

func (t Transit) Backup(ctx context.Context, keyName, engineName string) (string, error) {
	// TODO add error handling
	bp, err := t.lm.BackupPolicy(ctx, t.u.Storage(engineName), keyName)
	if err != nil {
		return "", err
	}

	return bp, nil
}
