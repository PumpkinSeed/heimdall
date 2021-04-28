package tests

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/PumpkinSeed/heimdall/cmd/flags"
	"github.com/PumpkinSeed/heimdall/cmd/server"
	"github.com/PumpkinSeed/heimdall/internal/socket"
	"github.com/PumpkinSeed/heimdall/internal/structs"
	initcommand "github.com/PumpkinSeed/heimdall/pkg/init"
	"github.com/urfave/cli/v2"
	"log"
	"os"
	"strings"
	"testing"
	"time"
)

func TestEncrypt(t *testing.T) {
	if runTest := os.Getenv("OVERALL"); runTest != "true" {
		t.Skip("Don't run overall test at this time")
	}
	set := flag.NewFlagSet("server", 0)
	set.String(flags.NameConsulToken, "89C2B840-CDE0-4E77-ACAF-73EABB7A489B", "doc")
	set.String(flags.NameConsulAddress, "127.0.0.1:8500", "doc")
	set.String(flags.NameGrpc, "0.0.0.0:9090", "doc")
	set.String(flags.NameRest, "0.0.0.0:10080", "doc")
	set.String(flags.NameSocket, "/tmp/mellek.sock", "doc")
	set.Int(flags.NameThreshold, 3, "doc")
	set.Int(flags.NameTotalShares, 5, "doc")
	ctx := cli.NewContext(nil, set, nil)

	var done chan struct{}
	go func (chan struct{}) {
		if err := server.Cmd.Action(ctx); err != nil {
			log.Print(err)
		}
		done <- struct{}{}
	} (done)

	time.Sleep(3*time.Second)

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

	fmt.Println(string(resp))
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


	//<- done
}
