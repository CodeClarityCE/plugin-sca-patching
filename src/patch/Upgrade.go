package patch

import (
	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	types "github.com/CodeClarityCE/plugin-sca-patching/src/types"
	"github.com/CodeClarityCE/plugin-sca-patching/src/types/patching"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	"github.com/uptrace/bun"
)

type Patcher struct {
	UpgradePolicy types.UpgradePolicy
	Knowledge     *bun.DB
	Sbom          sbomTypes.Output
	Vulns         vulnerabilityFinder.Output
	patching_info map[string]patching.PatchInfo
}

func InitializePatcher(upgradePolicy types.UpgradePolicy, knowledge *bun.DB, sbom sbomTypes.Output, vulns vulnerabilityFinder.Output) Patcher {
	return Patcher{
		UpgradePolicy: upgradePolicy,
		Knowledge:     knowledge,
		Sbom:          sbom,
		Vulns:         vulns,
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
