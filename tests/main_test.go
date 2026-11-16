package main

import (
	"testing"
	"time"

	"github.com/CodeClarityCE/plugin-sca-patching/internal/knowledgetest"
	patching "github.com/CodeClarityCE/plugin-sca-patching/src"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	"github.com/stretchr/testify/assert"
)

func TestCreateNPMv1(t *testing.T) {
	knowledge := knowledgetest.Open(t)

	sbom, err := getSBOM("../../js-sbom/tests/npmv1")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	vulns, err := getVulns("../../js-sbom/tests/npmv1")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	out := patching.Start(knowledge, sbom, vulns, "JS", time.Now())

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)
}

func TestCreateNPMv2(t *testing.T) {
	knowledge := knowledgetest.Open(t)

	sbom, err := getSBOM("../../js-sbom/tests/npmv2")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	vulns, err := getVulns("../../js-sbom/tests/npmv2")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	out := patching.Start(knowledge, sbom, vulns, "JS", time.Now())

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)
}

func TestCreateYarnv1(t *testing.T) {
	knowledge := knowledgetest.Open(t)

	sbom, err := getSBOM("../../js-sbom/tests/yarnv1")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	vulns, err := getVulns("../../js-sbom/tests/yarnv1")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	out := patching.Start(knowledge, sbom, vulns, "JS", time.Now())

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)
}

func TestCreateYarnv2(t *testing.T) {
	knowledge := knowledgetest.Open(t)

	sbom, err := getSBOM("../../js-sbom/tests/yarnv2")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	vulns, err := getVulns("../../js-sbom/tests/yarnv2")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	out := patching.Start(knowledge, sbom, vulns, "JS", time.Now())

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)
}

func TestCreateYarnv3(t *testing.T) {
	knowledge := knowledgetest.Open(t)

	sbom, err := getSBOM("../../js-sbom/tests/yarnv3")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	vulns, err := getVulns("../../js-sbom/tests/yarnv3")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	out := patching.Start(knowledge, sbom, vulns, "JS", time.Now())

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)
}

func TestCreateYarnv4(t *testing.T) {
	knowledge := knowledgetest.Open(t)

	sbom, err := getSBOM("../../js-sbom/tests/yarnv3")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	vulns, err := getVulns("../../js-sbom/tests/yarnv3")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	out := patching.Start(knowledge, sbom, vulns, "JS", time.Now())

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)
}

// func BenchmarkBigCreate(b *testing.B) {
// 	dsn_knowledge := dbhelper.BuildDSN("postgres", os.Getenv("PG_DB_PASSWORD"), "127.0.0.1", "5432", dbhelper.Config.Database.Knowledge)
// 	sqldb_knowledge := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn_knowledge)))
// 	db_knowledge := bun.NewDB(sqldb_knowledge, pgdialect.New())
// 	defer db_knowledge.Close()

// 	sbom, err := getSBOM("big")
// 	if err != nil {
// 		b.Errorf("Error getting mock SBOM: %v", err)
// 	}
// 	vulns, err := getVulns("../../js-sbom/tests/npmv1")
// 	if err != nil {
// 		b.Errorf("Error getting mock SBOM: %v", err)
// 	}

// 	out := patching.Start(db_knowledge, sbom, vulns, "JS", time.Now())

// 	if out.AnalysisInfo.Status != "success" {
// 		b.Errorf("Expected success, got %v", out.AnalysisInfo.Status)
// 	}

// 	// Write output to JSON file
// 	writeJSON(out, "output.json")
// }

// func writeJSON(data interface{}, filename string) error {
// 	jsonData, err := json.MarshalIndent(data, "", "  ")
// 	if err != nil {
// 		return err
// 	}

// 	err = os.WriteFile("test/results/"+filename, jsonData, 0644)
// 	if err != nil {
// 		return err
// 	}

// 	return nil
// }
