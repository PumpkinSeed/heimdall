package flags

import "github.com/urfave/cli/v2"

const (
	NameVerbose       = "verbose"
	NameLogOutput     = "log-output"
	NameLogAdditional = "log-additional"

	NameGrpc          = "grpc"
	NameRest          = "rest"
	NameSocket        = "socket"
	NameThreshold     = "threshold"
	NameConsulAddress = "consul-address"
	NameConsulToken   = "consul-token"
	NameInMemory      = "in-memory"

	grpcDefaultAddr   = "0.0.0.0:9090"
	restDefaultAddr   = "0.0.0.0:8080"
	socketDefaultPath = "/tmp/heimdall.sock"
	thresholdDefault  = 3
)

var (
	Verbose = &cli.BoolFlag{
		Name: NameVerbose,
	}
	LogOutput = &cli.StringFlag{
		Name:  NameLogOutput,
		Usage: "Set the log output",
		Value: "sout",
	}
	LogAdditional = &cli.StringFlag{
		Name:  NameLogAdditional,
		Usage: "Additional data for logger\nSyslog example: \"network=tcp;address=localhost:6060\"",
	}

	Grpc = &cli.StringFlag{
		Name:  NameGrpc,
		Usage: "Starts grpc server and listen on specified address",
		Value: grpcDefaultAddr,
	}
	Rest = &cli.StringFlag{
		Name:  NameRest,
		Usage: "Starts HTTP server and listen on specified address",
		Value: restDefaultAddr,
	}
	Socket = &cli.StringFlag{
		Name:  NameSocket,
		Usage: "Using the specified socket",
		Value: socketDefaultPath,
	}

	Threshold = &cli.IntFlag{
		Name:  NameThreshold,
		Usage: "The shamir's threshold",
		Value: thresholdDefault,
	}

	// TODO add flag to handle multiple database types
	ConsulAddress = &cli.StringFlag{
		Name:  NameConsulAddress,
		Usage: "Add consul's connection string here",
	}
	ConsulToken = &cli.StringFlag{
		Name:  NameConsulToken,
		Usage: "Add consul's access token here",
	}
	InMemory = &cli.BoolFlag{
		Name:  NameInMemory,
		Usage: "Starts the server with in memory physical backend for development",
		Value: false,
	}
)
