package flags

import "github.com/urfave/cli/v2"

const (
	NameGrpc = "grpc"
	NameRest = "rest"
)

var (
	Grpc = &cli.StringFlag{
		Name:  NameGrpc,
		Usage: "Starts grpc server and listen on specified address",
	}

	Rest = &cli.StringFlag{
		Name:  NameRest,
		Usage: "Starts HTTP server and listen on specified address",
	}
)
