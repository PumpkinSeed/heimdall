package utils

import (
	"regexp"

	"github.com/PumpkinSeed/heimdall/pkg/structs"
)

var EngineNameRegexp = regexp.MustCompile("^/[0-9a-v]+/")

func GetStatus(err error) structs.Status {
	if err != nil {
		return structs.Status_ERROR
	}

	return structs.Status_SUCCESS
}

func GetMessage(err error) string {
	if err != nil {
		return err.Error()
	}

	return "ok"
}
