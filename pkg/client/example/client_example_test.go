// +build integration

package client_example


import (
	"context"
	"fmt"

	"github.com/PumpkinSeed/heimdall/pkg/client"
	"github.com/PumpkinSeed/heimdall/pkg/client/grpc"
	"github.com/PumpkinSeed/heimdall/pkg/structs"
)

func ExampleNewGrpcClient() {
	c := client.New(grpc.Options{
		URLs: []string{"127.0.0.1:9000"},
		TLS:  false,
	})
	hash, _ := c.Hash(context.Background(), &structs.HashRequest{
		Input:     "asdf",
		Algorithm: "sha2-256",
	})
	fmt.Println(hash)
	// Output: f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b
}
