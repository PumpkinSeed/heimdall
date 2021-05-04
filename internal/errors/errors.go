package errors

import (
	"os"
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
	CodeCmdServerEnvSetup         Code = "030"
	CodeCmdServerEnvSetupPhysical Code = "0300"
	CodeCmdServerEnvSetupLogical  Code = "0301"
	CodeCmdServerExecute          Code = "031"
	CodeCmdUnseal                 Code = "04"

	CodeapiGrpc           Code = "10"
	CodeApiGrpcCreateKey  Code = "100"
	CodeApiGrpcReadKey    Code = "101"
	CodeApiGrpcDeleteKey  Code = "102"
	CodeApiGrpcListKey    Code = "103"
	CodeApiGrpcEncrypt    Code = "104"
	CodeApiGrpcDecrypt    Code = "105"
	CodeApiGrpcHash       Code = "106"
	CodeApiGrpcHMAC       Code = "107"
	CodeApiGrpcSign       Code = "108"
	CodeApiGrpcVerifySign Code = "109"
	CodeApiHTTP           Code = "11"
	CodeApiSocket         Code = "12"
)

type Code string

func NewErr(err error, code Code) error {
	return &Error{
		Msg:   err.Error(),
		Codes: []string{string(code)},
	}
}

func newErr(err error) error {
	return &Error{
		Msg: err.Error(),
	}
}

func New(errMsg string, code Code) error {
	return &Error{
		Msg:   errMsg,
		Codes: []string{string(code)},
	}
}

func Wrap(err error, msg string, code Code) error {
	if e, ok := err.(*Error); ok {
		if e.Msg != "" {
			e.Msg += "; " + msg
		} else {
			e.Msg = msg
		}
		e.Codes = append(e.Codes, string(code))

		return e
	}

	return Wrap(newErr(err), msg, code)
}

type Error struct {
	Msg   string
	Codes []string
}

func (h *Error) Error() string {
	sb := strings.Builder{}
	sb.WriteString("[")
	sb.WriteString(strings.Join(h.Codes, ","))
	sb.WriteString("]")
	sb.WriteString(" ")
	sb.WriteString(h.Msg)

	return sb.String()
}

func CliHandler(ctx *cli.Context, err error) {
	log.Error(Wrap(err, "fatal error", CodeCmd))
	os.Exit(1)
}