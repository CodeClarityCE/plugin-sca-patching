package patch

import (
	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	"github.com/CodeClarityCE/plugin-sca-patching/src/types/patching"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	matcher "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/vulnerabilityMatcher"
	"github.com/uptrace/bun"
)

type Patcher struct {
	Sbom          sbomTypes.Output
	Vulns         vulnerabilityFinder.Output
	registry      Registry
	checker       *vulnerabilityChecker
	patching_info map[string]patching.PatchInfo
}

// InitializePatcher reads package versions and advisories from the knowledge database.
func InitializePatcher(knowledge *bun.DB, sbom sbomTypes.Output, vulns vulnerabilityFinder.Output) Patcher {
	return newPatcher(dbRegistry{db: knowledge}, knowledge, nil, sbom, vulns)
}

// newPatcher builds a patcher on the given lookups; nil advisories read the knowledge database.
func newPatcher(registry Registry, knowledge *bun.DB, advisories matcher.Advisories, sbom sbomTypes.Output, vulns vulnerabilityFinder.Output) Patcher {
	return Patcher{
		Sbom:     sbom,
		Vulns:    vulns,
		registry: newCachedRegistry(registry),
		checker:  newVulnerabilityChecker(knowledge, advisories),
	}
}

func (patcher Patcher) PatchApplication() map[string]patching.Workspace {
	workspaceDataMap := map[string]patching.Workspace{}

	// Iterate over each workspace in the Sbom
	for workspaceKey := range patcher.Sbom.WorkSpaces {
		// Retrieve the top-level dependencies to patch for the current workspace
		dependenciesToPatch, devDependenciesToPatch := retrieveTopLevelDependenciesToPatch(patcher.Sbom.WorkSpaces[workspaceKey], patcher.Vulns.WorkSpaces[workspaceKey])

		// Patch the dependencies and devDependencies
		patches := patcher.PatchDependencies(dependenciesToPatch)
		devPatches := patcher.PatchDependencies(devDependenciesToPatch)

		// Create a new Workspace object and add it to the workspaceDataMap
		workspaceDataMap[workspaceKey] = patching.Workspace{
			Patches:    patches,
			DevPatches: devPatches,
		}
	}

	return workspaceDataMap

}
