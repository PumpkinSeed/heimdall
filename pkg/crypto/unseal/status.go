package unseal

import (
	"strconv"
	"strings"
)

type Status struct {
	TotalShares int
	Threshold   int
	Process     int
	Unsealed    bool
}

func (s Status) String() string {
	sb := strings.Builder{}
	if !s.Unsealed {
		sb.WriteString("Total shares: ")
		sb.WriteString(strconv.Itoa(s.TotalShares))
		sb.WriteString("\n")

		sb.WriteString("Threshold: ")
		sb.WriteString(strconv.Itoa(s.Threshold))
		sb.WriteString("\n")

		sb.WriteString("Process: ")
		sb.WriteString(strconv.Itoa(s.Process))
		sb.WriteString("/")
		sb.WriteString(strconv.Itoa(s.Threshold))
		sb.WriteString("\n")
	}

	sb.WriteString("Unsealed: ")
	sb.WriteString(strconv.FormatBool(s.Unsealed))
	sb.WriteString("\n")

	return sb.String()
}

