//go:build lean

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"go.k6.io/k6/v2/cmd/state"
)

// getCmdCloud returns a stub cloud command in the lean build.
func getCmdCloud(_ *state.GlobalState) *cobra.Command {
	return &cobra.Command{
		Use:   "cloud",
		Short: "Cloud functionality is not available in this lean build",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Usage()
		},
	}
}

// getCmdCloudLogin returns a stub cloud login command in the lean build.
func getCmdCloudLogin(_ *state.GlobalState) *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Cloud login is not available in this lean build",
		RunE: func(_ *cobra.Command, _ []string) error {
			return errCloudNotAvailable
		},
	}
}

// createCloudTest is a no-op in the lean build.
func createCloudTest(_ *state.GlobalState, _ *loadedAndConfiguredTest) error {
	return errCloudNotAvailable
}

var errCloudNotAvailable = fmt.Errorf("cloud functionality is not available in this lean build of k6")

// cloudRunCommandName mirrors the constant in cloud_run.go so that lean-build
// references in root.go continue to compile.
const cloudRunCommandName string = "run"
