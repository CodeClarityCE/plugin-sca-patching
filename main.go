package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	plugin "github.com/CodeClarityCE/plugin-sca-patching/src"
	"github.com/CodeClarityCE/plugin-sca-patching/src/types/patching"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	amqp_helper "github.com/CodeClarityCE/utility-amqp-helper"
	dbhelper "github.com/CodeClarityCE/utility-dbhelper/helper"
	types_amqp "github.com/CodeClarityCE/utility-types/amqp"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	"github.com/CodeClarityCE/utility-types/exceptions"
	exceptionManager "github.com/CodeClarityCE/utility-types/exceptions"
	plugin_db "github.com/CodeClarityCE/utility-types/plugin_db"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

// Define the arguments you want to pass to the callback function
type Arguments struct {
	codeclarity *bun.DB
	knowledge   *bun.DB
}

// main is the entry point of the program.
// It reads the configuration, initializes the necessary databases and graph,
// and starts listening on the queue.
func main() {
	config, err := readConfig()
	if err != nil {
		log.Printf("%v", err)
		return
	}

	host := os.Getenv("PG_DB_HOST")
	if host == "" {
		log.Printf("PG_DB_HOST is not set")
		return
	}
	port := os.Getenv("PG_DB_PORT")
	if port == "" {
		log.Printf("PG_DB_PORT is not set")
		return
	}
	user := os.Getenv("PG_DB_USER")
	if user == "" {
		log.Printf("PG_DB_USER is not set")
		return
	}
	password := os.Getenv("PG_DB_PASSWORD")
	if password == "" {
		log.Printf("PG_DB_PASSWORD is not set")
		return
	}

	dsn_knowledge := "postgres://" + user + ":" + password + "@" + host + ":" + port + "/" + dbhelper.Config.Database.Knowledge + "?sslmode=disable"
	sqldb_knowledge := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn_knowledge), pgdriver.WithTimeout(50*time.Second)))
	db_knowledge := bun.NewDB(sqldb_knowledge, pgdialect.New())
	defer db_knowledge.Close()

	dsn := "postgres://" + user + ":" + password + "@" + host + ":" + port + "/" + dbhelper.Config.Database.Results + "?sslmode=disable"
	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn), pgdriver.WithTimeout(50*time.Second)))
	db_codeclarity := bun.NewDB(sqldb, pgdialect.New())
	defer db_codeclarity.Close()

	args := Arguments{
		codeclarity: db_codeclarity,
		knowledge:   db_knowledge,
	}

	// Start listening on the queue
	amqp_helper.Listen("dispatcher_"+config.Name, callback, args, config)
}

// startAnalysis is a function that performs the analysis for a specific plugin.
// It takes the following parameters:
// - args: Arguments for the plugin.
// - dispatcherMessage: DispatcherPluginMessage containing information about the plugin message.
// - config: Plugin configuration.
// - analysis_document: Analysis document containing information about the analysis.
// It returns a map[string]any containing the result of the analysis, the analysis status, and an error if any.
func startAnalysis(args Arguments, dispatcherMessage types_amqp.DispatcherPluginMessage, config plugin_db.Plugin, analysis_document codeclarity.Analysis) (map[string]any, codeclarity.AnalysisStatus, error) {
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
			} else if step.Name == "js-vuln-finder" {
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
	sbom, err := getSbom(sbomKey, args)
	if err != nil {
		exceptionManager.AddError(
			"", exceptions.GENERIC_ERROR,
			fmt.Sprintf("Error when reading sbom output: %s", err), exceptions.FAILED_TO_READ_PREVIOUS_STAGE_OUTPUT,
		)
		return nil, codeclarity.FAILURE, err
	}

	// Retrieve the vulnerabilities from the previous stage
	vulns, err := getVulns(vulnKey, args)
	if err != nil {
		exceptionManager.AddError(
			"", exceptions.GENERIC_ERROR,
			fmt.Sprintf("Error when reading vulns output: %s", err), exceptions.FAILED_TO_READ_PREVIOUS_STAGE_OUTPUT,
		)
		return nil, codeclarity.FAILURE, err
	}

	patchingOutput = plugin.Start(args.knowledge, sbom, vulns, dbhelper.Config.Collection.JS, start)

	patch_result := codeclarity.Result{
		Result:     patching.ConvertOutputToMap(patchingOutput),
		AnalysisId: dispatcherMessage.AnalysisId,
		Plugin:     config.Name,
		CreatedOn:  time.Now(),
	}
	_, err = args.codeclarity.NewInsert().Model(&patch_result).Exec(context.Background())
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

func getVulns(vulnsKey uuid.UUID, args Arguments) (vulnerabilityFinder.Output, error) {
	res := codeclarity.Result{
		Id: vulnsKey,
	}
	err := args.codeclarity.NewSelect().Model(&res).Where("id = ?", vulnsKey).Scan(context.Background())
	if err != nil {
		panic(err)
	}
	vulns := vulnerabilityFinder.Output{}
	err = json.Unmarshal(res.Result.([]byte), &vulns)

	return vulns, err
}

func getSbom(sbomKey uuid.UUID, args Arguments) (sbomTypes.Output, error) {
	res := codeclarity.Result{
		Id: sbomKey,
	}
	err := args.codeclarity.NewSelect().Model(&res).Where("id = ?", sbomKey).Scan(context.Background())
	if err != nil {
		panic(err)
	}
	sbom := sbomTypes.Output{}
	err = json.Unmarshal(res.Result.([]byte), &sbom)

	return sbom, err
}
