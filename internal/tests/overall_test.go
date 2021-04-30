package tests

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/PumpkinSeed/heimdall/cmd/flags"
	"github.com/PumpkinSeed/heimdall/cmd/server"
	"github.com/PumpkinSeed/heimdall/internal/socket"
	"github.com/PumpkinSeed/heimdall/internal/structs"
	"github.com/PumpkinSeed/heimdall/pkg/client"
	"github.com/PumpkinSeed/heimdall/pkg/client/grpc"
	initcommand "github.com/PumpkinSeed/heimdall/pkg/init"
	externalStructs "github.com/PumpkinSeed/heimdall/pkg/structs"
	"github.com/urfave/cli/v2"
)

var force = false

func TestEncrypt(t *testing.T) {
	if runTest := os.Getenv("OVERALL"); force == false && runTest != "true" {
		t.Skip("Don't run overall test at this time")
	}
	set := flag.NewFlagSet("server", 0)
	set.String(flags.NameConsulToken, "89C2B840-CDE0-4E77-ACAF-73EABB7A489B", "doc")
	set.String(flags.NameConsulAddress, "127.0.0.1:8500", "doc")
	set.String(flags.NameGrpc, "0.0.0.0:9090", "doc")
	set.String(flags.NameHttp, "0.0.0.0:10080", "doc")
	set.String(flags.NameSocket, "/tmp/mellek.sock", "doc")
	set.Int(flags.NameThreshold, 3, "doc")
	set.Int(flags.NameTotalShares, 5, "doc")
	ctx := cli.NewContext(nil, set, nil)

	var done chan struct{}
	go func(chan struct{}) {
		if err := server.Cmd.Action(ctx); err != nil {
			log.Print(err)
		}
		done <- struct{}{}
	}(done)

	time.Sleep(3 * time.Second)

	initParams := initcommand.Request{
		SecretShares:    ctx.Int(flags.NameTotalShares),
		SecretThreshold: ctx.Int(flags.NameThreshold),
	}

	data, err := json.Marshal(initParams)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := socket.Do(ctx, structs.SocketRequest{
		Type: structs.SocketInit,
		Data: data,
	})

	log.Println(string(resp))
	type Result struct {
		SecretShares []string
		RootToken    string
	}
	var initResult Result
	if err := json.Unmarshal(resp, &initResult); err != nil {
		t.Error(err)
	}

	for _, key := range initResult.SecretShares {
		unsealResult, err := socket.Do(ctx, structs.SocketRequest{
			Type: structs.SocketUnseal,
			Data: []byte(key),
		})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(unsealResult), "Unsealed: true") {
			break
		}
	}

	hc := client.New(grpc.Options{
		TLS:  false,
		URLs: []string{"127.0.0.1:9090"},
	})

	keyname := "test1234"
	keyResp, err := hc.CreateKey(context.Background(), &externalStructs.Key{
		Name: keyname,
	})
	if err != nil {
		t.Error(err)
	}
	log.Println(keyResp)

	plaintext := "test"
	mes := time.Now()
	encryptResult, err := hc.Encrypt(context.Background(), &externalStructs.EncryptRequest{
		KeyName:   keyname,
		PlainText: plaintext,
	})
	if err != nil {
		t.Error(err)
	}
	log.Println("Encrypt time: " + time.Since(mes).String())

	mes = time.Now()
	decryptResult, err := hc.Decrypt(context.Background(), &externalStructs.DecryptRequest{
		KeyName:    keyname,
		Ciphertext: encryptResult.Result,
	})
	if err != nil {
		t.Error(err)
	}
	log.Println("Decrypt time: " + time.Since(mes).String())
	if decryptResult.Result != plaintext {
		t.Errorf("Decrypted result should be %s, instead of %s", plaintext, decryptResult.Result)
	}

	mes = time.Now()
	for i := 0; i < 100; i++ {
		_, err = hc.Encrypt(context.Background(), &externalStructs.EncryptRequest{
			KeyName:   keyname,
			PlainText: plaintext,
		})
		if err != nil {
			t.Error(err)
		}
	}
	log.Println("Encrypt 100 time: " + time.Since(mes).String())
	//<- done
}
