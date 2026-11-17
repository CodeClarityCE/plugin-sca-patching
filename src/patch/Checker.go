package patch

import (
	"slices"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	"github.com/CodeClarityCE/plugin-sca-vuln-finder/src/conflictResolver"
	ecosystemTypes "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/ecosystemAnalyzer/types"
	npmRepository "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/repository/npm"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	matcher "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/vulnerabilityMatcher"
	"github.com/uptrace/bun"
)

// vulnerabilityChecker finds what vuln-finder would report for package versions, remembering each answer.
type vulnerabilityChecker struct {
	knowledge  *bun.DB
	advisories matcher.Advisories
	found      map[string][]vulnerabilityFinder.Vulnerability
}

func newVulnerabilityChecker(knowledge *bun.DB, advisories matcher.Advisories) *vulnerabilityChecker {
	return &vulnerabilityChecker{knowledge: knowledge, advisories: advisories, found: map[string][]vulnerabilityFinder.Vulnerability{}}
}

// check returns the vulnerabilities of every version in tree (name -> versions), using vuln-finder's matching.
// A failed knowledge lookup returns an error, so the tree is never taken as clean.
func (c *vulnerabilityChecker) check(tree map[string][]string) ([]vulnerabilityFinder.Vulnerability, error) {
	unchecked := map[string]map[string]sbomTypes.Versions{}
	for name, versions := range tree {
		for _, version := range versions {
			if _, ok := c.found[name+"@"+version]; !ok {
				if unchecked[name] == nil {
					unchecked[name] = map[string]sbomTypes.Versions{}
				}
				unchecked[name][version] = sbomTypes.Versions{Direct: true}
			}
		}
	}
	if len(unchecked) > 0 {
		vm := matcher.VulnerabilityMatcher{
			Ecosystems:        []ecosystemTypes.Ecosystem{ecosystemTypes.NODEJS_OR_JS},
			ConflictResolver:  conflictResolver.TrustOSVFirst,
			PackageRepository: npmRepository.NpmPackageRepository,
			Advisories:        c.advisories,
		}
		vulnerabilities, _, err := vm.GetWorkspaceFindings(unchecked, c.knowledge)
		if err != nil {
			return nil, err
		}
		for name, versions := range unchecked {
			for version := range versions {
				c.found[name+"@"+version] = []vulnerabilityFinder.Vulnerability{}
			}
		}
		for _, vulnerability := range vulnerabilities {
			key := vulnerability.AffectedDependency + "@" + vulnerability.AffectedVersion
			c.found[key] = append(c.found[key], vulnerability)
		}
	}

	all := []vulnerabilityFinder.Vulnerability{}
	names := make([]string, 0, len(tree))
	for name := range tree {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		for _, version := range tree[name] {
			all = append(all, c.found[name+"@"+version]...)
		}
	}
	return all, nil
}
