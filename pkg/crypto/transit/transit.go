package transit

import (
	"github.com/hashicorp/vault/sdk/helper/keysutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/physical"
)

type Transit struct {
	lm      *keysutil.LockManager
	storage logical.Storage
}

func New(db physical.Backend) Transit {
	lm, err := keysutil.NewLockManager(false, 0)
	if err != nil {
		panic(err)
	}

	return Transit{
		lm:      lm,
		storage: logical.NewLogicalStorage(db),
	}
}

