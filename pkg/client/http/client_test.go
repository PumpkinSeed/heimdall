package http

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/PumpkinSeed/heimdall/pkg/structs"
)

func TestClient(t *testing.T) {
	opt := &Options{URLs: []string{"http://0.0.0.0:8080", "http://0.0.0.0:8080", "http://0.0.0.0:8080", "http://0.0.0.0:8080", "http://0.0.0.0:8080"}}
	client := opt.Setup()
	ctx := context.Background()
	key, err := client.CreateKey(ctx, &structs.Key{
		Name: fmt.Sprintf("some_key_%d", time.Now().UTC().UnixNano()),
		Type: structs.EncryptionType_AES256_GCM96,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(key)

	t.Logf("Key: %+v", key)
	keys, err := client.ListKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Keys: %+v", keys)

	k, err := client.ReadKey(ctx, key.Key.Name)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(k)

	k, err = client.ReadKey(ctx, key.Key.Name)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(k)

	const plainText = "ZWNyeXB0TWVJZllvdUNhbg==" // ecryptMeIfYouCan

	encrypt, err := client.Encrypt(ctx, &structs.EncryptRequest{
		KeyName:   key.Key.Name,
		PlainText: plainText,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Encrypted: %s", encrypt.Result)

	decrypt, err := client.Decrypt(ctx, &structs.DecryptRequest{
		KeyName:    key.Key.Name,
		Ciphertext: encrypt.Result,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Decrypted: %s", decrypt.Result)
}
