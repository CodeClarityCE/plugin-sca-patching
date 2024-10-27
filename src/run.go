package patching

import (
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
	"github.com/CodeClarityCE/plugin-sca-patching/src/types"
)

func Start(knowledge *bun.DB, sbom sbomTypes.Output, vulns vulnerabilityFinder.Output, languageId string, start time.Time) patching.Output {
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
		return outputGenerator.FailureOutput(sbom.AnalysisInfo, start)
	}

	// Initialize the patcher with specific upgrade policies
	upgradePolicy := types.UpgradePolicy{
		VersionSelectionPreference: types.SELECT_NEWEST,
		PartialFixVersionSelection: types.SELECT_LOWEST_AVERAGE_SEVERITY,
		AllowDowngrades:            false,
	}

	workSpaceData := patch.InitializePatcher(upgradePolicy, knowledge, sbom, vulns).PatchApplication()

	// Return a success output with the patched data
	return outputGenerator.SuccessOutput(workSpaceData, sbom.AnalysisInfo, start)
}
