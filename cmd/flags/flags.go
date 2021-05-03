package flags

import "github.com/urfave/cli/v2"

const (
	NameVerbose       = "verbose"
	NameLogOutput     = "log-output"
	NameLogAdditional = "log-additional"
	NameQuiet         = "quiet"

	NameGrpc              = "grpc"
	NameHttp              = "http"
	NameSocket            = "socket"
	NameThreshold         = "threshold"
	NameTotalShares       = "total-shares"
	NameDefaultEnginePath = "default-engine-path"
	NameConsulAddress     = "consul-address"
	NameConsulToken       = "consul-token"
	NameInMemory          = "in-memory"
	NameDisableHttp       = "disable-http"
	NameDisableGrpc       = "disable-grpc"

	grpcDefaultAddr    = "0.0.0.0:9090"
	httpDefaultAddr    = "0.0.0.0:8080"
	socketDefaultPath  = "/tmp/heimdall.sock"
	thresholdDefault   = 3
	totalSharesDefault = 5
	defaultEnginePath  = "transit/"
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
	Quiet = &cli.BoolFlag{
		Name:  NameQuiet,
		Usage: "Disable banner printing to logger's output",
	}

	Grpc = &cli.StringFlag{
		Name:  NameGrpc,
		Usage: "Starts grpc server and listen on specified address",
		Value: grpcDefaultAddr,
	}
	HTTP = &cli.StringFlag{
		Name:  NameHttp,
		Usage: "Starts HTTP server and listen on specified address",
		Value: httpDefaultAddr,
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

	TotalShares = &cli.IntFlag{
		Name:  NameTotalShares,
		Usage: "The shamir's total shares",
		Value: totalSharesDefault,
	}

	DefaultEnginePath = &cli.StringFlag{
		Name:  NameDefaultEnginePath,
		Usage: "If there are multiple secret engines mounted, choose one as default value",
		Value: defaultEnginePath,
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

	DisableGrpc = &cli.BoolFlag{
		Name:  NameDisableGrpc,
		Usage: "",
		Value: false,
	}

	DisableHttp = &cli.BoolFlag{
		Name:  NameDisableHttp,
		Usage: "",
		Value: false,
	}
)
