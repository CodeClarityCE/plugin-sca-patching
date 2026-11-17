package patch

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	semver "github.com/CodeClarityCE/utility-node-semver"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

// Package names are unique per language in the knowledge package table.
const packageLanguage = "javascript"

// Registry answers what the knowledge base knows about npm package versions.
type Registry interface {
	// Versions returns the package's stable versions in ascending order; none if the package is unknown.
	Versions(name string) ([]string, error)
	// Dependencies returns the production dependency constraints of one version; none if the version is unknown.
	Dependencies(name, version string) (map[string]string, error)
}

// dbRegistry reads package versions from the knowledge database.
type dbRegistry struct{ db *bun.DB }

func (r dbRegistry) Versions(name string) ([]string, error) {
	var rows []knowledge.Version
	err := r.db.NewSelect().
		Model(&rows).
		ColumnExpr("v.version").
		Join("JOIN package AS p ON p.id = v.package_id").
		Where("p.name = ?", name).
		Where("p.language = ?", packageLanguage).
		Scan(context.Background())
	if err != nil {
		return nil, err
	}
	stable := []string{}
	for _, row := range rows {
		if !strings.Contains(row.Version, "-") {
			stable = append(stable, row.Version)
		}
	}
	return semver.SortStrings(1, stable)
}

func (r dbRegistry) Dependencies(name, version string) (map[string]string, error) {
	row := new(knowledge.Version)
	err := r.db.NewSelect().
		Model(row).
		ColumnExpr("v.dependencies").
		Join("JOIN package AS p ON p.id = v.package_id").
		Where("p.name = ?", name).
		Where("p.language = ?", packageLanguage).
		Where("v.version = ?", version).
		Scan(context.Background())
	if errors.Is(err, sql.ErrNoRows) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	return row.Dependencies, nil
}

// laterVersions returns the stable versions released after installed, in ascending order.
func laterVersions(registry Registry, name, installed string) ([]string, error) {
	all, err := registry.Versions(name)
	if err != nil {
		return nil, err
	}
	current, err := semver.ParseSemver(installed)
	if err != nil {
		return nil, err
	}
	later := []string{}
	for _, version := range all {
		if parsed, err := semver.ParseSemver(version); err == nil && parsed.Compare(current, false) > 0 {
			later = append(later, version)
		}
	}
	return later, nil
}
