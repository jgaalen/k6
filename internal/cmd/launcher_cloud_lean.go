//go:build lean

package cmd

import (
	"go.k6.io/k6/v2/cmd/state"
)

// extractToken returns an empty token in the lean build since cloud functionality is not available.
func extractToken(_ *state.GlobalState) (string, error) {
	return "", nil
}
