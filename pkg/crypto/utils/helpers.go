package utils

import "github.com/PumpkinSeed/heimdall/pkg/structs"

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
