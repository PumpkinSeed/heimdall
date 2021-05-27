package utils

import "github.com/emvi/null"

func NullInt64FromPtr(v *int64) null.Int64 {
	if v == nil {
		return null.NewInt64(0, false)
	}
	return null.NewInt64(*v, true)
}

func NullBoolFromPtr(v *bool) null.Bool {
	if v == nil {
		return null.NewBool(false, false)
	}
	return null.NewBool(*v, true)
}
