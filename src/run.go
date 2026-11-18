package patching

import (
	"context"
	"time"

	outputGenerator "github.com/CodeClarityCE/plugin-sca-patching/src/outputGenerator"
	"github.com/CodeClarityCE/plugin-sca-patching/src/patch"
	"github.com/CodeClarityCE/plugin-sca-patching/src/types/patching"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	"github.com/CodeClarityCE/utility-types/exceptions"
	exceptionManager "github.com/CodeClarityCE/utility-types/exceptions"
	"github.com/uptrace/bun"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
)

// Start finds the upgrades for the sbom's vulnerable dependencies. A failed knowledge lookup returns
// a failed output and a patch.ErrKnowledgeLookup error, whose text must not be shown to users.
func Start(ctx context.Context, knowledge *bun.DB, sbom sbomTypes.Output, vulns vulnerabilityFinder.Output, languageId string, start time.Time, options patch.Options) (patching.Output, error) {
	// Check if the previous stage was successful
	if sbom.AnalysisInfo.Status != codeclarity.SUCCESS {
		// Add an error to the exception manager
		exceptionManager.AddError(
			"Execution of the previous stage was unsuccessful, upon which the current stage relies",
			exceptions.PREVIOUS_STAGE_FAILED,
			"Execution of the previous stage was unsuccessful, upon which the current stage relies",
			exceptions.PREVIOUS_STAGE_FAILED,
		)
		// Return a failure output
		return outputGenerator.FailureOutput(sbom.AnalysisInfo, start), nil
	}

	workSpaceData, err := patch.InitializePatcher(knowledge, sbom, vulns, options).PatchApplication(ctx)
	if err != nil {
		return outputGenerator.FailureOutput(sbom.AnalysisInfo, start), err
	}

	// Return a success output with the patched data
	return outputGenerator.SuccessOutput(workSpaceData, sbom.AnalysisInfo, start), nil
}
