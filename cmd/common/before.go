package common

import (
	"log/syslog"

	"github.com/PumpkinSeed/heimdall/cmd/flags"
	log "github.com/sirupsen/logrus"
	logrusSyslog "github.com/sirupsen/logrus/hooks/syslog"
	"github.com/urfave/cli/v2"
)

const (
	logOutputSyslog = "syslog"
)

func Before(ctx *cli.Context) error {
	if ctx.Bool(flags.NameVerbose) {
		log.SetLevel(log.DebugLevel)
	}
	if err := setFormatter(ctx); err != nil {
		return err
	}

	return nil
}

func setFormatter(ctx *cli.Context) error {
	if ctx.String(flags.NameLogOutput) == logOutputSyslog {
		hook, err := logrusSyslog.NewSyslogHook(
			ctx.String(flags.NameLogOutputNetwork),
			ctx.String(flags.NameLogOutputAddress), syslog.LOG_INFO, "")
		if err != nil {
			return err
		}
		log.AddHook(hook)
	}

	return nil
}
