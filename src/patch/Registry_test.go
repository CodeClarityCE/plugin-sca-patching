package patch

import (
	"testing"

	"github.com/CodeClarityCE/plugin-sca-patching/internal/knowledgetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests run the knowledge queries against a real knowledge database and skip without one.

func TestLaterVersionsListsNewerStableReleases(t *testing.T) {
	registry := dbRegistry{db: knowledgetest.Open(t)}

	versions, err := laterVersions(registry, "express", "4.16.0")
	require.NoError(t, err)
	require.NotEmpty(t, versions)

	assert.NotContains(t, versions, "4.16.0")
	assert.Equal(t, "4.16.1", versions[0])
	for _, v := range versions {
		assert.NotContains(t, v, "-", "pre-release %s should be filtered out", v)
	}
}

func TestVersionsOfUnknownPackageIsEmpty(t *testing.T) {
	registry := dbRegistry{db: knowledgetest.Open(t)}

	versions, err := registry.Versions("codeclarity-no-such-package")
	require.NoError(t, err)
	assert.Empty(t, versions)
}

func TestResolveTreeFollowsTransitiveDependencies(t *testing.T) {
	registry := dbRegistry{db: knowledgetest.Open(t)}

	tree, err := resolveTree(registry, "express", "4.16.0")
	require.NoError(t, err)

	// express 4.16.0 pins body-parser 1.18.2, which pins raw-body 2.3.2, which depends on bytes.
	assert.Equal(t, []string{"4.16.0"}, tree["express"])
	assert.Equal(t, []string{"1.18.2"}, tree["body-parser"])
	assert.Equal(t, []string{"2.3.2"}, tree["raw-body"])
	assert.Contains(t, tree, "bytes")
}
