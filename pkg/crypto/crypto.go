package crypto

import (
	"github.com/hashicorp/vault/sdk/physical"
)

type Crypto struct {
	backend physical.Backend

	masterKey []byte
}
