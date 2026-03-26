//go:build !lean

package cmd

import (
	"go.k6.io/k6/internal/output/cloud"
	"go.k6.io/k6/output"
)

// isCloudOutput returns true if the given output is the cloud output.
func isCloudOutput(o output.Output) bool {
	_, isCloud := o.(*cloud.Output)
	return isCloud
}
