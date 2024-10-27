package outputGenerator

import (
	"time"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	"github.com/CodeClarityCE/plugin-sca-patching/src/exceptionManager"
	"github.com/CodeClarityCE/plugin-sca-patching/src/types/patching"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
)

// SuccessOutput generates the output for a successful analysis.
// It takes in the workspaceData, analysisStats, sbomAnalysisInfo, and start time as parameters.
// It returns a patchingTypes.Output struct containing the workspace data, analysis information, and timing details.
func SuccessOutput(workspaceData map[string]patching.Workspace, sbomAnalysisInfo sbomTypes.AnalysisInfo, start time.Time) patching.Output {
	return patching.Output{
		WorkSpaces: workspaceData,
		AnalysisInfo: patching.AnalysisInfo{
			Status:            codeclarity.SUCCESS,
			AnalysisStartTime: start.Local().String(),
			AnalysisEndTime:   time.Now().Local().String(),
			AnalysisDeltaTime: time.Since(start).Seconds(),
			PrivateErrors:     exceptionManager.GetPrivateErrors(),
			PublicErrors:      exceptionManager.GetPublicErrors(),
		},
	}
}

// FailureOutput generates the output for a failed analysis.
// It takes the sbomAnalysisInfo and start time as input parameters.
// It returns an instance of patchingTypes.Output.
func FailureOutput(sbomAnalysisInfo sbomTypes.AnalysisInfo, start time.Time) patching.Output {
	formattedStart, formattedEnd, delta := getAnalysisTiming(start)
	output := patching.Output{
		AnalysisInfo: patching.AnalysisInfo{
			Status:            codeclarity.FAILURE,
			AnalysisStartTime: formattedStart,
			AnalysisEndTime:   formattedEnd,
			AnalysisDeltaTime: delta,
			PrivateErrors:     exceptionManager.GetPrivateErrors(),
			PublicErrors:      exceptionManager.GetPublicErrors(),
		},
		WorkSpaces: map[string]patching.Workspace{},
	}
	return output
}

// getAnalysisTiming calculates the start time, end time, and elapsed time of an analysis.
// It takes the start time as a parameter and returns the start time, end time, and elapsed time in seconds.
func getAnalysisTiming(start time.Time) (string, string, float64) {
	return start.Local().String(), time.Now().Local().String(), time.Since(start).Seconds()
}
