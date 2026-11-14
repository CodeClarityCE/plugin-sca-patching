package main

import (
	"testing"
	"time"

	"github.com/CodeClarityCE/plugin-sca-patching/internal/knowledgetest"
	patching "github.com/CodeClarityCE/plugin-sca-patching/src"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Fixtures are the js-sbom and vuln-finder results of the dev audit projects,
// with the large advisory payloads the patcher does not read stripped out.

func TestPatchesProjectWithVulnerabilities(t *testing.T) {
	knowledge := knowledgetest.Open(t)

	sbom, err := getSBOM("fixtures/audit-vuln-js")
	require.NoError(t, err)
	vulns, err := getVulns("fixtures/audit-vuln-js")
	require.NoError(t, err)
	require.NotEmpty(t, vulns.WorkSpaces["."].Vulnerabilities)

	out := patching.Start(knowledge, sbom, vulns, "JS", time.Now())

	require.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	patches := out.WorkSpaces["."].Patches
	require.NotEmpty(t, patches)

	// express 4.16.0 is a direct dependency with vulnerable transitive dependencies.
	express, ok := patches["express@4.16.0"]
	require.True(t, ok, "expected a patch entry for express@4.16.0, got %v", keys(patches))
	assert.Contains(t, []string{"FULL", "PARTIAL"}, express.IsPatchable)
	assert.NotEmpty(t, express.Update.String())

	for name, patch := range patches {
		assert.Contains(t, []string{"FULL", "PARTIAL", "NONE"}, patch.IsPatchable, "patch %s", name)
	}
}

func TestPatchesProjectWithoutVulnerabilities(t *testing.T) {
	knowledge := knowledgetest.Open(t)

	sbom, err := getSBOM("fixtures/audit-clean-js")
	require.NoError(t, err)
	vulns, err := getVulns("fixtures/audit-clean-js")
	require.NoError(t, err)

	out := patching.Start(knowledge, sbom, vulns, "JS", time.Now())

	require.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	require.Contains(t, out.WorkSpaces, ".")
	assert.Empty(t, out.WorkSpaces["."].Patches)
	assert.Empty(t, out.WorkSpaces["."].DevPatches)
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
