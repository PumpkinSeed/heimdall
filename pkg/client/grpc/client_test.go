package grpc

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/PumpkinSeed/heimdall/pkg/structs"
)

func TestClient(t *testing.T) {
	t.Skip("Skip integration test")
	client, err := Client("127.0.0.1:9090", Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	key, err := client.CreateKey(ctx, &structs.Key{
		Name: fmt.Sprintf("some_key_%d", time.Now().UTC().UnixNano()),
		Type: structs.EncryptionType_AES256_GCM96,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Key: %+v", key)
	keys, err := client.ListKeys(ctx, &structs.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Keys: %+v", keys)

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

func TestSignature(t *testing.T) {
	client, err := Client("127.0.0.1:9090", Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	key, err := client.CreateKey(ctx, &structs.Key{
		Name: fmt.Sprintf("some_key_%d", time.Now().UTC().UnixNano()),
		Type: structs.EncryptionType_ED25519,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Key: %+v", key)
	keys, err := client.ListKeys(ctx, &structs.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Keys: %+v", keys)

	const plainText = "ZWNyeXB0TWVJZllvdUNhbg==" // ecryptMeIfYouCan
	signRes, err := client.Sign(ctx,&structs.SignParameters{
		KeyName:            key.Key.Name,
		KeyVersion:         1,
		HashAlgorithm:      structs.HashType_HashTypeSHA2256,
		Input:              plainText,
		Context:            "",
		Prehashed:          false,
		SignatureAlgorithm: "",
	})
	if err != nil {
		t.Error(err)
	}
	fmt.Println(signRes)

	verificationResp, err := client.VerifySigned(ctx,&structs.VerificationRequest{
		KeyName:            key.Key.Name,
		HashAlgorithm:      structs.HashType_HashTypeSHA2256,
		Input:              plainText,
		Signature:          signRes.Result,
		Context:            "",
		Prehashed:          false,
		SignatureAlgorithm: "",
	})
	if err != nil {
		t.Error(err)
	}
	fmt.Println(verificationResp)
}
