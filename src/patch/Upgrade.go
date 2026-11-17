package patch

import (
	"context"
	"time"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	"github.com/CodeClarityCE/plugin-sca-patching/src/types/patching"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	matcher "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/vulnerabilityMatcher"
	"github.com/sirupsen/logrus"
	"github.com/uptrace/bun"
)

type Patcher struct {
	Sbom          sbomTypes.Output
	Vulns         vulnerabilityFinder.Output
	registry      Registry
	checker       *vulnerabilityChecker
	log           *logrus.Entry
	patching_info map[string]patching.PatchInfo
}

// Options configures one patching run.
type Options struct {
	// Log receives the run's log lines, carrying the analysis id; nil logs to the standard logger.
	Log *logrus.Entry
	// KnowledgeAsOf, when set, ignores advisories published after that day, as vuln-finder did.
	KnowledgeAsOf *time.Time
}

// InitializePatcher reads package versions and advisories from the knowledge database.
func InitializePatcher(knowledge *bun.DB, sbom sbomTypes.Output, vulns vulnerabilityFinder.Output, options Options) Patcher {
	return newPatcher(dbRegistry{db: knowledge}, knowledge, nil, sbom, vulns, options)
}

// newPatcher builds a patcher on the given lookups; nil advisories read the knowledge database.
func newPatcher(registry Registry, knowledge *bun.DB, advisories matcher.Advisories, sbom sbomTypes.Output, vulns vulnerabilityFinder.Output, options Options) Patcher {
	log := options.Log
	if log == nil {
		log = logrus.NewEntry(logrus.StandardLogger())
	}
	return Patcher{
		Sbom:     sbom,
		Vulns:    vulns,
		registry: newCachedRegistry(registry),
		checker:  newVulnerabilityChecker(knowledge, advisories, options.KnowledgeAsOf),
		log:      log,
	}
}

// PatchApplication finds the upgrades of every workspace. A failed knowledge lookup returns an
// ErrKnowledgeLookup error, whose text holds the raw database error and must not be shown to users.
func (patcher Patcher) PatchApplication(ctx context.Context) (map[string]patching.Workspace, error) {
	workspaceDataMap := map[string]patching.Workspace{}

	for workspaceKey := range patcher.Sbom.WorkSpaces {
		dependenciesToPatch, devDependenciesToPatch := retrieveTopLevelDependenciesToPatch(patcher.Sbom.WorkSpaces[workspaceKey], patcher.Vulns.WorkSpaces[workspaceKey])

		patches, err := patcher.PatchDependencies(ctx, dependenciesToPatch)
		if err != nil {
			return nil, err
		}
		devPatches, err := patcher.PatchDependencies(ctx, devDependenciesToPatch)
		if err != nil {
			return nil, err
		}

		workspaceDataMap[workspaceKey] = patching.Workspace{
			Patches:    patches,
			DevPatches: devPatches,
		}
	}

	return workspaceDataMap, nil
}
