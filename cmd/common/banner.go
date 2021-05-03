package common

import (
	"os"

	"github.com/PumpkinSeed/heimdall/cmd/flags"
	"github.com/dimiro1/banner"
	"github.com/urfave/cli/v2"
)

func initBanner(ctx *cli.Context) {
	banner.InitString(os.Stdout, !ctx.Bool(flags.NameDisableBanner), true, bannerTempl)
}

const bannerTempl = `{{ .Title "Heimdall" "" 4 }}
{{ .AnsiColor.BrightCyan }}All-Fathers, let the dark magic flow through me one last time.{{ .AnsiColor.Default }}
GoVersion: {{ .GoVersion }}
GOOS: {{ .GOOS }}
GOARCH: {{ .GOARCH }}
NumCPU: {{ .NumCPU }}
GOPATH: {{ .GOPATH }}
GOROOT: {{ .GOROOT }}
Compiler: {{ .Compiler }}
ENV: {{ .Env "GOPATH" }}
Now: {{ .Now "2006-01-01" }}
{{ .AnsiColor.BrightBlue }}There is always hope.{{ .AnsiColor.Default }}
`
