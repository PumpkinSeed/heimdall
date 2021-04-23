package common

import (
	"errors"
	"log/syslog"
	"regexp"

	"github.com/PumpkinSeed/heimdall/cmd/flags"
	log "github.com/sirupsen/logrus"
	logrusSyslog "github.com/sirupsen/logrus/hooks/syslog"
	"github.com/urfave/cli/v2"
)

const (
	logOutputSyslog  = "syslog"
	syslogKeyAddress = "address"
	syslogKeyNetwork = "network"
)

func Before(ctx *cli.Context) error {
	if ctx.Bool(flags.NameVerbose) {
		log.SetLevel(log.DebugLevel)
	}
	if err := setupHook(ctx); err != nil {
		return err
	}

	return nil
}

func setupHook(ctx *cli.Context) error {
	switch ctx.String(flags.NameLogOutput) {
	case logOutputSyslog:
		prot, addr, err := bindSyslogAdditional(ctx.String(flags.NameLogAdditional))
		if err != nil {
			return err
		}
		hook, err := logrusSyslog.NewSyslogHook(prot, addr, syslog.LOG_INFO, "")
		if err != nil {
			return err
		}
		log.AddHook(hook)
	}

	return nil
}

func bindSyslogAdditional(data string) (string, string, error) {
	var properties = make(map[string]string, 2)
	syslogPattern := regexp.MustCompile("(([a-zA-Z]+)=([a-zA-Z0-9:/]+);?)")
	groups := syslogPattern.FindAllStringSubmatch(data, -1)
	for i := range groups {
		properties[groups[i][2]] = groups[i][3]
	}
	var addr, network string
	var ok bool
	if addr, ok = properties[syslogKeyAddress]; !ok {
		return "", "", errors.New("missing address from additional")
	}
	if network, ok = properties[syslogKeyNetwork]; !ok {
		return "", "", errors.New("missing network type from additional")
	}

	return addr, network, nil
}
