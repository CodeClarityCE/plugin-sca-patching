package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	plugin "github.com/CodeClarityCE/plugin-sca-patching/src"
	"github.com/CodeClarityCE/plugin-sca-patching/src/patch"
	"github.com/CodeClarityCE/plugin-sca-patching/src/types/patching"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	"github.com/CodeClarityCE/utility-boilerplates"
	dbhelper "github.com/CodeClarityCE/utility-dbhelper/helper"
	types_amqp "github.com/CodeClarityCE/utility-types/amqp"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	plugin_db "github.com/CodeClarityCE/utility-types/plugin_db"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
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

const (
	knowledgeLookupReason = "the vulnerability database could not be read, try the analysis again"
	missingSbomReason     = "the dependency list could not be read"
	missingVulnsReason    = "the vulnerability results could not be read"
	saveReason            = "the patching results could not be saved"
)

// stepFailure logs the raw cause and returns a failed step that carries a readable reason.
func stepFailure(log *logrus.Entry, reason string, cause error) (map[string]any, codeclarity.AnalysisStatus, error) {
	log.WithError(cause).Error("Patching failed: " + reason)
	return map[string]any{codeclarity.StepFailureReasonKey: reason}, codeclarity.FAILURE, nil
}

// previousResults reads the js-sbom and vuln-finder result keys, and the knowledge date vuln-finder used.
// On error, reason says which result could not be read.
func previousResults(analysis codeclarity.Analysis) (sbomKey, vulnKey uuid.UUID, knowledgeAsOf *time.Time, reason string, err error) {
	for _, stage := range analysis.Steps {
		for _, step := range stage {
			switch step.Name {
			case "js-sbom":
				raw, _ := step.Result["sbomKey"].(string)
				if sbomKey, err = uuid.Parse(raw); err != nil {
					return sbomKey, vulnKey, nil, missingSbomReason, fmt.Errorf("invalid js-sbom key %q: %w", raw, err)
				}
			case "vuln-finder":
				raw, _ := step.Result["vulnKey"].(string)
				if vulnKey, err = uuid.Parse(raw); err != nil {
					return sbomKey, vulnKey, nil, missingVulnsReason, fmt.Errorf("invalid vuln-finder key %q: %w", raw, err)
				}
				if asOf, ok := step.Result["knowledgeAsOf"].(string); ok && asOf != "" {
					parsed, err := time.Parse("2006-01-02", asOf)
					if err != nil {
						return sbomKey, vulnKey, nil, missingVulnsReason, fmt.Errorf("invalid vuln-finder knowledgeAsOf %q: %w", asOf, err)
					}
					knowledgeAsOf = &parsed
				}
			}
		}
	}
	return sbomKey, vulnKey, knowledgeAsOf, "", nil
}

// startAnalysis finds the upgrades for the vulnerabilities vuln-finder reported on the js-sbom result.
func startAnalysis(databases *boilerplates.PluginDatabases, dispatcherMessage types_amqp.DispatcherPluginMessage, config plugin_db.Plugin, analysis_document codeclarity.Analysis) (map[string]any, codeclarity.AnalysisStatus, error) {
	log := logrus.WithField("analysis_id", dispatcherMessage.AnalysisId.String())
	ctx := context.Background()

	sbomKey, vulnKey, knowledgeAsOf, reason, err := previousResults(analysis_document)
	if err != nil {
		return stepFailure(log, reason, err)
	}

	start := time.Now()

	sbom, err := getSbom(ctx, sbomKey, databases)
	if err != nil {
		return stepFailure(log, missingSbomReason, err)
	}
	vulns, err := getVulns(ctx, vulnKey, databases)
	if err != nil {
		return stepFailure(log, missingVulnsReason, err)
	}

	patchingOutput, err := plugin.Start(ctx, databases.Knowledge, sbom, vulns, dbhelper.Config.Collection.JS, start, patch.Options{
		Log:           log,
		KnowledgeAsOf: knowledgeAsOf,
	})
	failureReason := ""
	if err != nil {
		log.WithError(err).Error("Patching failed: " + knowledgeLookupReason)
		failureReason = knowledgeLookupReason
	}

	patch_result := codeclarity.Result{
		Result:     patching.ConvertOutputToMap(patchingOutput),
		AnalysisId: dispatcherMessage.AnalysisId,
		Plugin:     config.Name,
		CreatedOn:  time.Now(),
	}
	if _, err := databases.Codeclarity.NewInsert().Model(&patch_result).Exec(ctx); err != nil {
		if failureReason == "" {
			failureReason = saveReason
		}
		return stepFailure(log, failureReason, fmt.Errorf("failed to insert patching result: %w", err))
	}

	// Later plugins read the result by its key.
	result := map[string]any{"patchKey": patch_result.Id}
	if failureReason != "" {
		result[codeclarity.StepFailureReasonKey] = failureReason
	}
	return result, patchingOutput.AnalysisInfo.Status, nil
}

func getVulns(ctx context.Context, vulnsKey uuid.UUID, databases *boilerplates.PluginDatabases) (vulnerabilityFinder.Output, error) {
	res := codeclarity.Result{Id: vulnsKey}
	if err := databases.Codeclarity.NewSelect().Model(&res).Where("id = ?", vulnsKey).Scan(ctx); err != nil {
		return vulnerabilityFinder.Output{}, err
	}
	raw, ok := res.Result.([]byte)
	if !ok {
		return vulnerabilityFinder.Output{}, fmt.Errorf("vuln-finder result %s is %T", vulnsKey, res.Result)
	}
	vulns := vulnerabilityFinder.Output{}
	err := json.Unmarshal(raw, &vulns)
	return vulns, err
}

func getSbom(ctx context.Context, sbomKey uuid.UUID, databases *boilerplates.PluginDatabases) (sbomTypes.Output, error) {
	res := codeclarity.Result{Id: sbomKey}
	if err := databases.Codeclarity.NewSelect().Model(&res).Where("id = ?", sbomKey).Scan(ctx); err != nil {
		return sbomTypes.Output{}, err
	}
	raw, ok := res.Result.([]byte)
	if !ok {
		return sbomTypes.Output{}, fmt.Errorf("js-sbom result %s is %T", sbomKey, res.Result)
	}
	sbom := sbomTypes.Output{}
	err := json.Unmarshal(raw, &sbom)
	return sbom, err
}
