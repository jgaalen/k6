//go:build lean

package cmd

import (
	"go.k6.io/k6/output"
)

// isCloudOutput always returns false in the lean build since the cloud output is not included.
func isCloudOutput(_ output.Output) bool {
	return false
}
