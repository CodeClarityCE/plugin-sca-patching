package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	plugin "github.com/CodeClarityCE/plugin-sca-patching/src"
	"github.com/CodeClarityCE/plugin-sca-patching/src/types/patching"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	dbhelper "github.com/CodeClarityCE/utility-dbhelper/helper"
	types_amqp "github.com/CodeClarityCE/utility-types/amqp"
	"github.com/CodeClarityCE/utility-types/boilerplates"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	"github.com/CodeClarityCE/utility-types/exceptions"
	exceptionManager "github.com/CodeClarityCE/utility-types/exceptions"
	plugin_db "github.com/CodeClarityCE/utility-types/plugin_db"
	"github.com/google/uuid"
)

// JSPatchingAnalysisHandler implements the AnalysisHandler interface
type JSPatchingAnalysisHandler struct{}

// StartAnalysis implements the AnalysisHandler interface
func (h *JSPatchingAnalysisHandler) StartAnalysis(
	databases *boilerplates.PluginDatabases,
	dispatcherMessage types_amqp.DispatcherPluginMessage,
	config plugin_db.Plugin,
	analysisDoc codeclarity.Analysis,
) (map[string]any, codeclarity.AnalysisStatus, error) {
	return startAnalysis(databases, dispatcherMessage, config, analysisDoc)
}

// main is the entry point of the program.
func main() {
	pluginBase, err := boilerplates.CreatePluginBase()
	if err != nil {
		log.Fatalf("Failed to initialize plugin base: %v", err)
	}
	defer pluginBase.Close()

	// Start the plugin with our analysis handler
	handler := &JSPatchingAnalysisHandler{}
	err = pluginBase.Listen(handler)
	if err != nil {
		log.Fatalf("Failed to start plugin: %v", err)
	}
}

// startAnalysis is a function that performs the analysis for a specific plugin.
// It takes the following parameters:
// - args: Arguments for the plugin.
// - dispatcherMessage: DispatcherPluginMessage containing information about the plugin message.
// - config: Plugin configuration.
// - analysis_document: Analysis document containing information about the analysis.
// It returns a map[string]any containing the result of the analysis, the analysis status, and an error if any.
func startAnalysis(databases *boilerplates.PluginDatabases, dispatcherMessage types_amqp.DispatcherPluginMessage, config plugin_db.Plugin, analysis_document codeclarity.Analysis) (map[string]any, codeclarity.AnalysisStatus, error) {
	// Prepare the arguments for the plugin

	// Get sbomKey from previous stage
	sbomKey := uuid.UUID{}
	vulnKey := uuid.UUID{}
	for _, stage := range analysis_document.Steps {
		for _, step := range stage {
			if step.Name == "js-sbom" {
				sbomKeyUUID, err := uuid.Parse(step.Result["sbomKey"].(string))
				if err != nil {
					panic(err)
				}
				sbomKey = sbomKeyUUID
				break
			} else if step.Name == "vuln-finder" {
				vulnKeyUUID, err := uuid.Parse(step.Result["vulnKey"].(string))
				if err != nil {
					panic(err)
				}
				vulnKey = vulnKeyUUID
				break
			}
		}
	}

	var patchingOutput patching.Output

	start := time.Now()

	// Retrieve the sbom from the previous stage
	sbom, err := getSbom(sbomKey, databases)
	if err != nil {
		exceptionManager.AddError(
			"", exceptions.GENERIC_ERROR,
			fmt.Sprintf("Error when reading sbom output: %s", err), exceptions.FAILED_TO_READ_PREVIOUS_STAGE_OUTPUT,
		)
		return nil, codeclarity.FAILURE, err
	}

	// Retrieve the vulnerabilities from the previous stage
	vulns, err := getVulns(vulnKey, databases)
	if err != nil {
		exceptionManager.AddError(
			"", exceptions.GENERIC_ERROR,
			fmt.Sprintf("Error when reading vulns output: %s", err), exceptions.FAILED_TO_READ_PREVIOUS_STAGE_OUTPUT,
		)
		return nil, codeclarity.FAILURE, err
	}

	patchingOutput = plugin.Start(databases.Knowledge, sbom, vulns, dbhelper.Config.Collection.JS, start)

	patch_result := codeclarity.Result{
		Result:     patching.ConvertOutputToMap(patchingOutput),
		AnalysisId: dispatcherMessage.AnalysisId,
		Plugin:     config.Name,
		CreatedOn:  time.Now(),
	}
	_, err = databases.Codeclarity.NewInsert().Model(&patch_result).Exec(context.Background())
	if err != nil {
		panic(err)
	}

	// Prepare the result to store in step
	// In this case we only store the sbomKey
	// The other plugins will use this key to get the sbom
	result := make(map[string]any)
	result["patchKey"] = patch_result.Id

	// The output is always a map[string]any
	return result, patchingOutput.AnalysisInfo.Status, nil
}

func getVulns(vulnsKey uuid.UUID, databases *boilerplates.PluginDatabases) (vulnerabilityFinder.Output, error) {
	res := codeclarity.Result{
		Id: vulnsKey,
	}
	err := databases.Codeclarity.NewSelect().Model(&res).Where("id = ?", vulnsKey).Scan(context.Background())
	if err != nil {
		panic(err)
	}
	vulns := vulnerabilityFinder.Output{}
	err = json.Unmarshal(res.Result.([]byte), &vulns)

	return vulns, err
}

func getSbom(sbomKey uuid.UUID, databases *boilerplates.PluginDatabases) (sbomTypes.Output, error) {
	res := codeclarity.Result{
		Id: sbomKey,
	}
	err := databases.Codeclarity.NewSelect().Model(&res).Where("id = ?", sbomKey).Scan(context.Background())
	if err != nil {
		panic(err)
	}
	sbom := sbomTypes.Output{}
	err = json.Unmarshal(res.Result.([]byte), &sbom)

	return sbom, err
}
