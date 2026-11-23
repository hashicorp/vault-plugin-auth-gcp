// Copyright IBM Corp. 2017, 2025
// SPDX-License-Identifier: MPL-2.0

package gcpauth

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCLIHandler_Help verifies that Help uses BinaryName in the commands it
// shows and falls back to "vault" when it's unset.
func TestCLIHandler_Help(t *testing.T) {
	t.Parallel()

	require.Contains(t, (&CLIHandler{}).Help(), "vault login -method=gcp")

	help := (&CLIHandler{BinaryName: "vault-client"}).Help()
	require.Contains(t, help, "vault-client login -method=gcp")
	require.NotContains(t, help, "vault login")
}
