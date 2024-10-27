package main

import (
	"database/sql"
	"testing"
	"time"

	patching "github.com/CodeClarityCE/plugin-sca-patching/src"
	dbhelper "github.com/CodeClarityCE/utility-dbhelper/helper"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	"github.com/stretchr/testify/assert"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

func TestCreateNPMv1(t *testing.T) {
	dsn_knowledge := "postgres://postgres:!ChangeMe!@127.0.0.1:6432/" + dbhelper.Config.Database.Knowledge + "?sslmode=disable"
	sqldb_knowledge := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn_knowledge), pgdriver.WithTimeout(50*time.Second)))
	db_knowledge := bun.NewDB(sqldb_knowledge, pgdialect.New())
	defer db_knowledge.Close()

	sbom, err := getSBOM("../../js-sbom/tests/npmv1")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	vulns, err := getVulns("../../js-sbom/tests/npmv1")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	out := patching.Start(db_knowledge, sbom, vulns, "JS", time.Now())

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)
}

func TestCreateNPMv2(t *testing.T) {
	dsn_knowledge := "postgres://postgres:!ChangeMe!@127.0.0.1:6432/" + dbhelper.Config.Database.Knowledge + "?sslmode=disable"
	sqldb_knowledge := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn_knowledge), pgdriver.WithTimeout(50*time.Second)))
	db_knowledge := bun.NewDB(sqldb_knowledge, pgdialect.New())
	defer db_knowledge.Close()

	sbom, err := getSBOM("../../js-sbom/tests/npmv2")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	vulns, err := getVulns("../../js-sbom/tests/npmv2")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	out := patching.Start(db_knowledge, sbom, vulns, "JS", time.Now())

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)
}

func TestCreateYarnv1(t *testing.T) {
	dsn_knowledge := "postgres://postgres:!ChangeMe!@127.0.0.1:6432/" + dbhelper.Config.Database.Knowledge + "?sslmode=disable"
	sqldb_knowledge := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn_knowledge), pgdriver.WithTimeout(50*time.Second)))
	db_knowledge := bun.NewDB(sqldb_knowledge, pgdialect.New())
	defer db_knowledge.Close()

	sbom, err := getSBOM("../../js-sbom/tests/yarnv1")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	vulns, err := getVulns("../../js-sbom/tests/yarnv1")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	out := patching.Start(db_knowledge, sbom, vulns, "JS", time.Now())

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)
}

func TestCreateYarnv2(t *testing.T) {
	dsn_knowledge := "postgres://postgres:!ChangeMe!@127.0.0.1:6432/" + dbhelper.Config.Database.Knowledge + "?sslmode=disable"
	sqldb_knowledge := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn_knowledge), pgdriver.WithTimeout(50*time.Second)))
	db_knowledge := bun.NewDB(sqldb_knowledge, pgdialect.New())
	defer db_knowledge.Close()

	sbom, err := getSBOM("../../js-sbom/tests/yarnv2")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	vulns, err := getVulns("../../js-sbom/tests/yarnv2")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	out := patching.Start(db_knowledge, sbom, vulns, "JS", time.Now())

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)
}

func TestCreateYarnv3(t *testing.T) {
	dsn_knowledge := "postgres://postgres:!ChangeMe!@127.0.0.1:6432/" + dbhelper.Config.Database.Knowledge + "?sslmode=disable"
	sqldb_knowledge := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn_knowledge), pgdriver.WithTimeout(50*time.Second)))
	db_knowledge := bun.NewDB(sqldb_knowledge, pgdialect.New())
	defer db_knowledge.Close()

	sbom, err := getSBOM("../../js-sbom/tests/yarnv3")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	vulns, err := getVulns("../../js-sbom/tests/yarnv3")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	out := patching.Start(db_knowledge, sbom, vulns, "JS", time.Now())

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)
}

func TestCreateYarnv4(t *testing.T) {
	dsn_knowledge := "postgres://postgres:!ChangeMe!@127.0.0.1:6432/" + dbhelper.Config.Database.Knowledge + "?sslmode=disable"
	sqldb_knowledge := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn_knowledge), pgdriver.WithTimeout(50*time.Second)))
	db_knowledge := bun.NewDB(sqldb_knowledge, pgdialect.New())
	defer db_knowledge.Close()

	sbom, err := getSBOM("../../js-sbom/tests/yarnv3")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	vulns, err := getVulns("../../js-sbom/tests/yarnv3")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	out := patching.Start(db_knowledge, sbom, vulns, "JS", time.Now())

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)
}

// func BenchmarkBigCreate(b *testing.B) {
// 	dsn_knowledge := "postgres://postgres:!ChangeMe!@127.0.0.1:5432/" + dbhelper.Config.Database.Knowledge + "?sslmode=disable"
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
