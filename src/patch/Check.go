package patch

import (
	"slices"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	"github.com/CodeClarityCE/plugin-sca-patching/src/types/patching"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
)

func retrieveTopLevelDependenciesToPatch(sbom sbomTypes.WorkSpace, vulns vulnerabilityFinder.Workspace) (map[string][]patching.ToPatch, map[string][]patching.ToPatch) {

	return addDependenciesToPatch(sbom.Start.Dependencies, sbom, vulns), addDependenciesToPatch(sbom.Start.DevDependencies, sbom, vulns)

}

func recursiveFindDependenciesToPatch(version sbomTypes.Versions, sbom sbomTypes.WorkSpace, vulnerabilities []vulnerabilityFinder.Vulnerability, toPatch []patching.ToPatch, path []string) []patching.ToPatch {
	if slices.Contains(path, version.Key) {
		return toPatch
	}

	new_path := make([]string, len(path))
	copy(new_path, path)
	new_path = append(new_path, version.Key)

	for _, vulnerability := range vulnerabilities {
		if version.Key == vulnerability.AffectedDependency+"@"+vulnerability.AffectedVersion {
			toPatch = append(toPatch, newToPatch(vulnerability, new_path))
		}
	}
	for dependency_name, dependency_version := range version.Dependencies {
		version = sbom.Dependencies[dependency_name][dependency_version]
		toPatch = recursiveFindDependenciesToPatch(version, sbom, vulnerabilities, toPatch, new_path)
	}
	return toPatch
}

func addDependenciesToPatch(dependencies []sbomTypes.WorkSpaceDependency, sbom sbomTypes.WorkSpace, vulns vulnerabilityFinder.Workspace) map[string][]patching.ToPatch {
	toPatch := make(map[string][]patching.ToPatch)
	for _, dependency := range dependencies {

		version := sbom.Dependencies[dependency.Name][dependency.Version]
		var toPatchArray []patching.ToPatch

		res := recursiveFindDependenciesToPatch(version, sbom, vulns.Vulnerabilities, toPatchArray, []string{})
		if len(res) > 0 {
			toPatch[dependency.Name+"@"+dependency.Version] = res
		}
	}
	return toPatch
}

// newToPatch records one vulnerable occurrence with the fix its advisory names.
func newToPatch(vulnerability vulnerabilityFinder.Vulnerability, path []string) patching.ToPatch {
	occurrence := patching.ToPatch{
		DependencyName:    vulnerability.AffectedDependency,
		DependencyVersion: vulnerability.AffectedVersion,
		Path:              path,
		Vulnerability:     patching.TrimVulnerability(vulnerability),
	}
	if fixed, ok := getClosestNonVulnerable(vulnerability.NVDMatch, vulnerability.OSVMatch); ok {
		occurrence.AdvisoryFix = &fixed
	}
	return occurrence
}
