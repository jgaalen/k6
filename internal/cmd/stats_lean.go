//go:build lean

package cmd

import (
	"errors"

	"github.com/spf13/cobra"

	"go.k6.io/k6/v2/cmd/state"
)

// getCmdStats returns a stub stats command in the lean build, since the REST
// API server (which it queries) is not built.
func getCmdStats(_ *state.GlobalState) *cobra.Command {
	return &cobra.Command{
		Use:    "stats",
		Short:  "Show test metrics (not available in this lean build)",
		Hidden: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return errors.New("the stats command is not available in this lean build of k6")
		},
	}
}
