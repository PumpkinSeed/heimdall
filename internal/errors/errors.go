package errors

import (
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

const (
	CodeCmd                       Code = "0"
	CodeCmdCommon                 Code = "00"
	CodeCmdCommonBefore           Code = "000"
	CodeCmdCommonSetupBind        Code = "001"
	CodeCmdCommonSetupSyslogHook  Code = "002"
	CodeCmdCommonSetupBindAddress Code = "003"
	CodeCmdCommonSetupBindNetwork Code = "004"
	CodeCmdFlags                  Code = "01"
	CodeCmdInit                   Code = "02"
	CodeCmdServer                 Code = "03"
	CodeCmdUnseal                 Code = "04"
)

type Code string

func NewErr(err error, code Code) error {
	return &HeimdallError{
		Msg:   err.Error(),
		Codes: []string{string(code)},
	}
}

func newErr(err error) error {
	return &HeimdallError{
		Msg: err.Error(),
	}
}

func New(errMsg string, code Code) error {
	return &HeimdallError{
		Msg:   errMsg,
		Codes: []string{string(code)},
	}
}

func Wrap(err error, msg string, code Code) error {
	if e, ok := err.(*HeimdallError); ok {
		if e.Msg != "" {
			e.Msg += ": " + msg
		} else {
			e.Msg = msg
		}
		e.Codes = append(e.Codes, string(code))

		return e
	}

	return Wrap(newErr(err), msg, code)
}

type HeimdallError struct {
	Msg   string
	Codes []string
}

func (h *HeimdallError) Error() string {
	sb := strings.Builder{}
	sb.WriteString("[")
	sb.WriteString(strings.Join(h.Codes, ","))
	sb.WriteString("]")
	sb.WriteString(h.Msg)

	return sb.String()
}

func CliHandler(ctx *cli.Context, err error) {
	log.Error(Wrap(err, "fatal error", CodeCmd))
}
