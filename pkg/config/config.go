package config

import (
	"os"
)

const (
	vaultUrlEnv                    = "VAULT_URL"
	serviceAccountTokenFileEnv     = "SERVICE_ACCOUNT_TOKEN_FILE"
	serviceAccountTokenFileDefault = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

func VaultUrl() string {
	val, _ := os.LookupEnv(vaultUrlEnv)
	return val
}

func ServiceAccountTokenFile() string {
	val, ok := os.LookupEnv(serviceAccountTokenFileEnv)
	if !ok {
		return serviceAccountTokenFileDefault
	}
	return val
}
