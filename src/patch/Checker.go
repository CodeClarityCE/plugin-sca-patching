package patch

import (
	"cmp"
	"context"
	"slices"
	"time"

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
	// knowledgeAsOf, when set, ignores advisories published after that day, as vuln-finder did.
	knowledgeAsOf *time.Time
	found         map[string][]vulnerabilityFinder.Vulnerability
}

func newVulnerabilityChecker(knowledge *bun.DB, advisories matcher.Advisories, knowledgeAsOf *time.Time) *vulnerabilityChecker {
	return &vulnerabilityChecker{knowledge: knowledge, advisories: advisories, knowledgeAsOf: knowledgeAsOf, found: map[string][]vulnerabilityFinder.Vulnerability{}}
}

// load checks, in one vuln-finder call, every package version of the trees not checked yet.
// A failed knowledge lookup returns an error, so no tree is ever taken as clean.
func (c *vulnerabilityChecker) load(ctx context.Context, trees []resolvedTree) error {
	unchecked := map[string]map[string]sbomTypes.Versions{}
	for _, tree := range trees {
		for name, versions := range tree.versions {
			for _, version := range versions {
				if _, ok := c.found[name+"@"+version]; ok {
					continue
				}
				if unchecked[name] == nil {
					unchecked[name] = map[string]sbomTypes.Versions{}
				}
				unchecked[name][version] = sbomTypes.Versions{Direct: true}
			}
		}
	}
	if len(unchecked) == 0 {
		return nil
	}
	vm := matcher.VulnerabilityMatcher{
		Ecosystems:        []ecosystemTypes.Ecosystem{ecosystemTypes.NODEJS_OR_JS},
		ConflictResolver:  conflictResolver.TrustOSVFirst,
		PackageRepository: npmRepository.NpmPackageRepository,
		KnowledgeAsOf:     c.knowledgeAsOf,
		Advisories:        c.advisories,
	}
	vulnerabilities, _, err := vm.GetWorkspaceFindings(ctx, unchecked, c.knowledge)
	if err != nil {
		return knowledgeLookupError(err)
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
	for name, versions := range unchecked {
		for version := range versions {
			slices.SortFunc(c.found[name+"@"+version], func(a, b vulnerabilityFinder.Vulnerability) int {
				return cmp.Compare(a.VulnerabilityId, b.VulnerabilityId)
			})
		}
	}
	return nil
}

// vulnerabilities returns the vulnerabilities load found in the tree, in package name order.
func (c *vulnerabilityChecker) vulnerabilities(tree resolvedTree) []vulnerabilityFinder.Vulnerability {
	all := []vulnerabilityFinder.Vulnerability{}
	names := make([]string, 0, len(tree.versions))
	for name := range tree.versions {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		for _, version := range tree.versions[name] {
			all = append(all, c.found[name+"@"+version]...)
		}
	}
	return all
}
