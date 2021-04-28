package transit

import (
	"context"
	"testing"

	"github.com/PumpkinSeed/heimdall/pkg/crypto/unseal"
	"github.com/hashicorp/vault/sdk/physical/inmem"
	"github.com/hashicorp/vault/vault"
	"github.com/stretchr/testify/assert"
)

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
	u := unseal.Get()
	u.SetSecurityBarrier(barrier)
	if err := u.DevMode(ctx); err != nil {
		t.Fatal(err)
	}

	tr := New(u)

	const keyName = "testkey"
	if err := tr.CreateKey(ctx, keyName, "", "transit/"); err != nil {
		t.Fatal(err)
	}

	const plainText = "ZWNyeXB0TWVJZllvdUNhbg==" // ecryptMeIfYouCan

	encrypt, err := tr.Encrypt(ctx, keyName, "transit/", BatchRequestItem{
		Plaintext:  plainText,
		KeyVersion: 0,
	})
	if err != nil {
		t.Fatal(err)
	}

	assert.NotEmpty(t, encrypt.Ciphertext)

	decrypt, err := tr.Decrypt(ctx, keyName, "transit/", BatchRequestItem{
		Ciphertext: encrypt.Ciphertext,
		KeyVersion: encrypt.KeyVersion,
	})
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, plainText, decrypt.Plaintext)

}
