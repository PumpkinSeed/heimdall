package init

import (
	"github.com/PumpkinSeed/heimdall/pkg/crypto/unseal"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/physical/inmem"
	"github.com/hashicorp/vault/vault"
	"testing"
)

var masterKey = []byte{189, 121, 77, 142, 213, 195, 183, 143, 119, 147, 168, 188, 242, 216, 180,
	245, 110, 118, 183, 203, 72, 121, 94, 174, 222, 164, 209, 240, 156, 246, 22, 109}

func TestInitialize(t *testing.T) {
	db, err := inmem.NewInmem(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	barrier, err := vault.NewAESGCMBarrier(db)
	if err != nil {
		t.Fatal(err)
	}
	b, err := inmem.NewInmem(nil, logging.NewVaultLogger(hclog.Debug))
	if err != nil {
		t.Fatal(err)
	}
	u := unseal.Get()
	u.SetSecurityBarrier(barrier)
	u.SetBackend(b)
	//u.SetMasterKey(masterKey)
	//if err := u.PostProcess(ctx, ""); err != nil {
	//	t.Fatal(err)
	//}

	if err := Initialize(); err != nil {
		t.Fatal(err)
	}
}
