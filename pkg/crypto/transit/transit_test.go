package transit

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/helper/keysutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

func TestTransit(t *testing.T) {
	ctx := context.Background()
	inmem := &logical.InmemStorage{}
	lm, _ := keysutil.NewLockManager(false, 0)
	tr := Transit{
		lm:      lm,
		storage: inmem,
	}

	const keyName = "testkey"
	if err := tr.CreateKey(ctx, keyName, ""); err != nil {
		t.Fatal(err)
	}

	const plainText = "ZWNyeXB0TWVJZllvdUNhbg==" // ecryptMeIfYouCan

	encrypt, err := tr.Encrypt(ctx, keyName, BatchRequestItem{
		Plaintext:  plainText,
		KeyVersion: 0,
	})
	if err != nil {
		t.Fatal(err)
	}

	assert.NotEmpty(t, encrypt.Ciphertext)

	decrypt, err := tr.Decrypt(ctx, keyName, BatchRequestItem{
		Ciphertext: encrypt.Ciphertext,
		KeyVersion: encrypt.KeyVersion,
	})
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, plainText, decrypt.Plaintext)

}
