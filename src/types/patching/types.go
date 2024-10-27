package patching

import (
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	"github.com/CodeClarityCE/utility-node-semver/versions"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	"github.com/CodeClarityCE/utility-types/exceptions"
)

type PatchType string

const (
	FULL    PatchType = "FULL"
	PARTIAL PatchType = "PARTIAL"
	NONE    PatchType = "NONE"
)

type SeverityDist struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	None     int `json:"none"`
}

type IntroductionType string

const (
	ExistedBefore   = "EXISTED_BEFORE"
	NewlyIntroduced = "NEWLY_INTRODUCED"
	Mixed           = "MIXED"
)

type AnalysisInfo struct {
	Status                   codeclarity.AnalysisStatus `json:"status"`
	PrivateErrors            []exceptions.PrivateError  `json:"private_errors"`
	PublicErrors             []exceptions.PublicError   `json:"public_errors"`
	AnalysisStartTime        string                     `json:"analysis_start_time"`
	AnalysisEndTime          string                     `json:"analysis_end_time"`
	AnalysisDeltaTime        float64                    `json:"analysis_delta_time"`
	VersionSeperator         string                     `json:"version_seperator"`
	ImportPathSeperator      string                     `json:"import_path_seperator"`
	DefaultWorkspaceName     string                     `json:"default_workspace_name"`
	SelfManagedWorkspaceName string                     `json:"self_managed_workspace_name"`
}

type Upgrades struct {
	Name          string `json:"name,omitempty"`
	OldConstraint string `json:"old_constraint,omitempty"`
	NewConstraint string `json:"new_constraint,omitempty"`
	Reapply       bool   `json:"reapply,omitempty"`
}

type ToPatch struct {
	DependencyName    string
	DependencyVersion string
	Path              []string
	Vulnerability     vulnerabilityFinder.Vulnerability
}

type PatchInfo struct {
	TopLevelVulnerable bool
	IsPatchable        string
	Unpatchable        []ToPatch
	Patchable          []ToPatch
	Introduced         []ToPatch
	Patches            map[string]versions.Semver
	Update             versions.Semver
}

type Workspace struct {
	Patches    map[string]PatchInfo `json:"patches"`
	DevPatches map[string]PatchInfo `json:"dev_patches"`
}

type Output struct {
	WorkSpaces   map[string]Workspace `json:"workspaces"`
	AnalysisInfo AnalysisInfo         `json:"analysis_info"`
}

func ConvertOutputToMap(output Output) map[string]interface{} {
	result := make(map[string]interface{})

	// Convert workspaces to map
	workspaces := make(map[string]interface{})
	for workspaceName, workspaceData := range output.WorkSpaces {
		workspace := make(map[string]interface{})
		workspace["patches"] = workspaceData.Patches
		workspace["dev_patches"] = workspaceData.DevPatches
		workspaces[workspaceName] = workspace
	}
	result["workspaces"] = workspaces

	// Convert analysis info
	result["analysis_info"] = output.AnalysisInfo

	return result
}
