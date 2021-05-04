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

	CodeApiGrpc                       Code = "10"
	CodeApiGrpcCreateKey              Code = "100"
	CodeApiGrpcReadKey                Code = "101"
	CodeApiGrpcDeleteKey              Code = "102"
	CodeApiGrpcListKey                Code = "103"
	CodeApiGrpcEncrypt                Code = "104"
	CodeApiGrpcDecrypt                Code = "105"
	CodeApiGrpcHash                   Code = "106"
	CodeApiGrpcHMAC                   Code = "107"
	CodeApiGrpcSign                   Code = "108"
	CodeApiGrpcVerifySign             Code = "109"
	CodeApiHTTP                       Code = "11"
	CodeApiHTTPBind                   Code = "110"
	CodeApiHTTPBindRead               Code = "1100"
	CodeApiHTTPBindUnmarshal          Code = "1101"
	CodeApiHTTPSuccessResponse        Code = "111"
	CodeApiHTTPSuccessResponseMarshal Code = "1110"
	CodeApiHTTPSuccessResponseWrite   Code = "1111"
	CodeApiHTTPCreateKey              Code = "112"
	CodeApiHTTPCreateKeyEngineName    Code = "1120"
	CodeApiHTTPReadKey                Code = "113"
	CodeApiHTTPReadKeyEngineName      Code = "1130"
	CodeApiHTTPDeleteKey              Code = "114"
	CodeApiHTTPDeleteKeyEngineName    Code = "1140"
	CodeApiHTTPListKeys               Code = "115"
	CodeApiHTTPListKeysEngineName     Code = "1150"
	CodeApiHTTPEncrypt                Code = "116"
	CodeApiHTTPEncryptEngineName      Code = "1160"
	CodeApiHTTPDecrypt                Code = "117"
	CodeApiHTTPDecryptEngineName      Code = "1170"
	CodeApiHTTPHash                   Code = "118"
	CodeApiHTTPHmac                   Code = "119"
	CodeApiHTTPHmacEngineName         Code = "1190"
	CodeApiHTTPSign                   Code = "11_10_"
	CodeApiHTTPSignEngineName         Code = "11_10_0"
	CodeApiHTTPVerifySign             Code = "11_11_"
	CodeApiHTTPVerifySignEngineName   Code = "11_11_0"
	CodeApiSocket                     Code = "12"
	CodeApiSocketBind                 Code = "120"
	CodeApiSocketBindRead             Code = "1200"
	CodeApiSocketBindUnmarshal        Code = "1201"
	CodeApiSocketBindUnknown          Code = "1202"
	CodeApiSocketWrite                Code = "121"
	CodeApiSocketHandler              Code = "122"
	CodeApiSocketInit                 Code = "123"
	CodeApiSocketInitUnmarshal        Code = "1230"
	CodeApiSocketInitMarshal          Code = "1231"
	CodeApiSocketUnseal               Code = "124"
	CodeApiSocketUnsealKeyring        Code = "1241"
	CodeApiSocketUnsealMount          Code = "1242"
	CodeApiSocketUnsealPostProcess    Code = "1243"

	CodeClient               Code = "2"
	CodeClientGrpc           Code = "20"
	CodeClientGrpcDial       Code = "200"
	CodeClientGrpcTLSError   Code = "201"
	CodeClientGrpcCreateKey  Code = "202"
	CodeClientGrpcReadKey    Code = "203"
	CodeClientGrpcDeleteKey  Code = "204"
	CodeClientGrpcListKey    Code = "205"
	CodeClientGrpcEncrypt    Code = "206"
	CodeClientGrpcDecrypt    Code = "207"
	CodeClientGrpcHash       Code = "208"
	CodeClientGrpcHmac       Code = "209"
	CodeClientGrpcSign       Code = "209"
	CodeClientGrpcVerifySign Code = "20_10_"

	CodeClientHttp                   Code = "21"
	CodeClientHttpSetup              Code = "210"
	CodeClientHttpSetupCreateClient  Code = "2100"
	CodeClientHttpSetupCloneClient   Code = "2101"
	CodeClientHttpCreateKey          Code = "211"
	CodeClientHttpReadKey            Code = "212"
	CodeClientHttpDeleteKey          Code = "213"
	CodeClientHttpListKey            Code = "214"
	CodeClientHttpEncrypt            Code = "215"
	CodeClientHttpDecrypt            Code = "216"
	CodeClientHttpHash               Code = "217"
	CodeClientHttpHmac               Code = "218"
	CodeClientHttpSign               Code = "219"
	CodeClientHttpVerifySign         Code = "21_10_"
	CodeClientHttpHealth             Code = "21_11_"
	CodeClientHttpHealthVaultRequest Code = "21_11_0"
	CodeClientHttpHealthRead         Code = "21_11_1"
	CodeClientHttpHealthUnmarshal    Code = "21_11_2"

	CodePkgCrypto Code = "3"

	CodePkgHealthcheck Code = "4"

	CodePkgInit Code = "5"

	CodePkgSeal Code = "6"

	CodePkgStorage Code = "7"

	CodeInternal Code = "8" // TODO
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
