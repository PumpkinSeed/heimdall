package transit

import (
	"context"
	"testing"

	"github.com/PumpkinSeed/heimdall/pkg/crypto/unseal"
	"github.com/hashicorp/vault/sdk/physical/inmem"
	"github.com/hashicorp/vault/vault"
	"github.com/stretchr/testify/assert"
)

var masterKey = []byte{189, 121, 77, 142, 213, 195, 183, 143, 119, 147, 168, 188, 242, 216, 180,
	245, 110, 118, 183, 203, 72, 121, 94, 174, 222, 164, 209, 240, 156, 246, 22, 109}

func TestTransit(t *testing.T) {
	ctx := context.Background()
	db, err := inmem.NewInmem(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	barrier, err := vault.NewAESGCMBarrier(db)
	if err != nil {
		t.Fatal(err)
	}
	u := &unseal.Unseal{}
	u.SetSecurityBarrier(barrier)
	u.SetMasterKey(masterKey)

	if err := u.PostProcess(ctx, []string{""}); err != nil {
		t.Fatal(err)
	}

	tr := New(u)

	const keyName = "testkey"
	if err := tr.CreateKey(ctx, keyName, "", ""); err != nil {
		t.Fatal(err)
	}

	const plainText = "ZWNyeXB0TWVJZllvdUNhbg==" // ecryptMeIfYouCan

	encrypt, err := tr.Encrypt(ctx, keyName, "", BatchRequestItem{
		Plaintext:  plainText,
		KeyVersion: 0,
	})
	if err != nil {
		t.Fatal(err)
	}

	assert.NotEmpty(t, encrypt.Ciphertext)

	decrypt, err := tr.Decrypt(ctx, keyName, "", BatchRequestItem{
		Ciphertext: encrypt.Ciphertext,
		KeyVersion: encrypt.KeyVersion,
	})
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, plainText, decrypt.Plaintext)

}
