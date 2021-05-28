package dev

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/PumpkinSeed/heimdall/pkg/structs"
	"github.com/rs/xid"
	"github.com/stretchr/testify/assert"
)

func TestSetup(t *testing.T) {
	client := Options{}.Setup()
	assert.NotNil(t, client)
}

func TestOverAll(t *testing.T) {
	client := Options{}.Setup()
	ctx := context.Background()

	keyName := "test_key_" + xid.New().String()

	key, err := client.CreateKey(ctx, &structs.Key{
		Name: keyName,
	})
	assert.NoError(t, err)
	assert.Equal(t, keyName, key.Key.Name, "create key")

	readKey, err := client.ReadKey(ctx, keyName)
	assert.NoError(t, err)
	assert.Equal(t, key.Key.Name, readKey.Key.Name, "read key")

	keys, err := client.ListKeys(ctx)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(keys.Keys), "keys length")
	assert.Equal(t, keyName, keys.Keys[0].Name)

	plainText := base64.StdEncoding.EncodeToString([]byte("textForEncrypt"))

	encrypt, err := client.Encrypt(ctx, &structs.EncryptRequest{
		KeyName:    keyName,
		PlainText:  plainText,
		KeyVersion: 0,
	})
	assert.NoError(t, err)
	assert.NotEmpty(t, encrypt.Result, "encrypt result")

	decrypt, err := client.Decrypt(ctx, &structs.DecryptRequest{
		KeyName:    keyName,
		Ciphertext: encrypt.Result,
		KeyVersion: 0,
	})
	assert.NoError(t, err)
	assert.Equal(t, plainText, decrypt.Result, "decrpyt result")
}
