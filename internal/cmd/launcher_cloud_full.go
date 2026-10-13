//go:build !lean

package cmd

import (
	"go.k6.io/k6/v2/cloudapi"
	"go.k6.io/k6/v2/cmd/state"
)

// extractToken gets the cloud token required to access the build service
// from the environment or from the config file
func extractToken(gs *state.GlobalState) (string, error) {
	diskConfig, err := readDiskConfig(gs)
	if err != nil {
		return "", err
	}

	config, _, err := cloudapi.GetConsolidatedConfig(diskConfig.Collectors["cloud"], gs.Env, "", nil)
	if err != nil {
		return "", err
	}

	return config.Token.String, nil
}
