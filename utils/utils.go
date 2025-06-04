package utils

import (
	"strconv"
	"strings"
)

func Must[T any](v T, err error) T {
	// panics if any error is returned
	if err != nil {
		panic(err)
	}
	return v
}

func GetApiKey() string {
	return Must(GetEnv("INVISIRISK_JWT_TOKEN","ENV variable forINVISIRISK_JWT_TOKEN not found."))
}

func GetPolicyUrl() string {
	baseUrl:= Must(GetEnv("INVISIRISK_PORTAL", "ENV variable for INVISIRISK_PORTAL not found."))

	return baseUrl + "/ingestionapi/v1/get-policies"
}

func StrToFloat(s string) float32 {	
	if cl := strings.TrimSpace(s); cl != "" {
		if i, err := strconv.ParseFloat(cl, 32); err == nil {
			return float32(i)
		}
	}
	return 0
}

