package config

import (
	"fmt"
	"os"
)

const (
	spiUrlEnv              = "SPI_URL"
	bearerTokenFileEnv     = "SPI_BEARER_TOKEN_FILE"
	defaultBearerTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

func SpiUrl() string {
	ret, _ := os.LookupEnv(spiUrlEnv)
	return ret
}

func BearerTokenFile() string {
	ret, ok := os.LookupEnv(bearerTokenFileEnv)
	if !ok {
		return defaultBearerTokenFile
	}

	return ret
}

func ValidateEnv() error {
	if _, ok := os.LookupEnv(spiUrlEnv); !ok {
		return fmt.Errorf("the following environment variables are mandatory: %s", spiUrlEnv)
	}

	return nil
}
