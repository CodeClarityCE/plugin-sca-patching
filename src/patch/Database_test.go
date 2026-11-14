package patch

import (
	"strings"
	"testing"

	"github.com/CodeClarityCE/plugin-sca-patching/internal/knowledgetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests run the knowledge queries against a real knowledge database and skip without one.

func TestGetPossibleVersionsListsNewerStableReleases(t *testing.T) {
	patcher := Patcher{Knowledge: knowledgetest.Open(t)}

	versions, err := patcher.getPossibleVersions("express", "4.16.0")
	require.NoError(t, err)
	require.NotEmpty(t, versions)

	assert.NotContains(t, versions, "4.16.0")
	assert.Contains(t, versions, "4.16.1")
	for _, v := range versions {
		assert.NotContains(t, v, "-", "pre-release %s should be filtered out", v)
	}
}

func TestGetPossibleVersionsOfUnknownPackageIsEmpty(t *testing.T) {
	patcher := Patcher{Knowledge: knowledgetest.Open(t)}

	versions, err := patcher.getPossibleVersions("codeclarity-no-such-package", "0.0.0")
	require.NoError(t, err)
	assert.Empty(t, versions)
}

func TestGetTransitiveDependenciesResolvesPinnedVersions(t *testing.T) {
	patcher := Patcher{Knowledge: knowledgetest.Open(t)}

	prod, _, err := patcher.getTransitiveDependencies("express", "4.16.0")
	require.NoError(t, err)
	require.NotEmpty(t, prod)

	// express 4.16.0 pins body-parser 1.18.2 exactly.
	assert.Contains(t, prod, "body-parser@1.18.2")
	for _, dep := range prod {
		assert.True(t, strings.Contains(dep, "@"), "expected name@version, got %s", dep)
	}
}

func TestGetNVDVulnerabilitiesFindsKnownCVEs(t *testing.T) {
	patcher := Patcher{Knowledge: knowledgetest.Open(t)}

	count, items, err := patcher.GetNVDVulnerabilities("lodash", "4.17.4")
	require.NoError(t, err)
	assert.Equal(t, len(items), count)

	ids := []string{}
	for _, item := range items {
		ids = append(ids, item.NVDId)
	}
	// Prototype pollution, fixed in lodash 4.17.12.
	assert.Contains(t, ids, "CVE-2019-10744")
}
