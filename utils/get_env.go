package utils

import (
	"fmt"
	"os"

	"github.com/open-policy-agent/opa/logging"
)
func GetEnv(key, errorMsg string) (string, error) {
	/*
		Helper function to get env variable, and log if not found
	*/
	log := logging.New()

	value := os.Getenv(key)
	if value == "" {
		log.Error("ERROR: %s", errorMsg)
		return "", fmt.Errorf("%s", errorMsg)
	}
	return value, nil
}