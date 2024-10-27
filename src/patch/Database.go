package patch

import (
	"context"
	"fmt"
	"strings"

	matcher "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/vulnerabilityMatcher"
	nvdMatcher "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/vulnerabilityMatcher/nvd"
	semver "github.com/CodeClarityCE/utility-node-semver"
	"github.com/CodeClarityCE/utility-node-semver/constraints"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

// This function retrieves possible versions of a dependency based on the provided parameters.
func (patcher Patcher) getTransitiveDependencies(dependencyName string, dependencyVersion string) ([]string, []string, error) {
	version := new(knowledge.Version)

	// Execute a SELECT query using the knowledge base.
	err := patcher.Knowledge.RunInTx(context.Background(), nil, func(ctx context.Context, tx bun.Tx) error {
		return tx.NewSelect().
			Model(version).
			ColumnExpr("pv.dependencies, pv.dev_dependencies").
			Join("JOIN package AS p ON p.id = pv.\"packageId\"").
			Where("p.name = ?", dependencyName).
			Where("pv.version = ?", dependencyVersion).
			Scan(context.Background())
	})

	if err != nil {
		return nil, nil, err
	}

	prodDependencies := []string{}
	for dep_name, dep_constraint_string := range version.Dependencies {
		dep_versions, err := patcher.getPossibleVersions(dep_name, "0.0.0")
		if err != nil {
			return nil, nil, err
		}
		if len(dep_versions) == 0 {
			// TODO check why this happens
			continue
		}

		if strings.Contains(dep_constraint_string, "file:") {
			err := fmt.Errorf("file managed")
			return nil, nil, err
		}
		constraint, err := semver.ParseConstraint(dep_constraint_string)
		if err != nil {
			if err == constraints.ErrInvalidVersion {
				continue
			}
			return nil, nil, err
		}
		satisfying_version, err := semver.MaxSatisfyingStrings(dep_versions, constraint, false)
		if err != nil {
			return nil, nil, err
		}
		prodDependencies = append(prodDependencies, dep_name+"@"+satisfying_version.String())
	}

	devDependencies := []string{}
	for dep_name, dep_constraint_string := range version.DevDependencies {
		dep_versions, err := patcher.getPossibleVersions(dep_name, "0.0.0")
		if err != nil {
			return nil, nil, err
		}
		if len(dep_versions) == 0 {
			continue
		}
		constraint, err := semver.ParseConstraint(dep_constraint_string)
		if err != nil {
			if err == constraints.ErrInvalidVersion {
				continue
			}
			return nil, nil, err
		}
		satisfying_version, err := semver.MaxSatisfyingStrings(dep_versions, constraint, false)
		if err != nil {
			return nil, nil, err
		}
		devDependencies = append(devDependencies, dep_name+"@"+satisfying_version.String())
	}
	return prodDependencies, devDependencies, nil
}

// This function retrieves possible versions of a dependency based on the provided parameters.
func (patcher Patcher) getPossibleVersions(dependencyName string, dependencyVersion string) ([]string, error) {
	var versions []knowledge.Version

	// Execute a SELECT query using the knowledge base.
	err := patcher.Knowledge.RunInTx(context.Background(), nil, func(ctx context.Context, tx bun.Tx) error {
		return tx.NewSelect().
			Model(&versions).
			ColumnExpr("pv.version, pv.id, pv.\"packageId\"").
			Join("JOIN package AS p ON p.id = pv.\"packageId\"").
			Where("p.name = ?", dependencyName).
			Scan(context.Background())
	})

	if err != nil {
		return nil, err
	}

	var versionFields []string
	for _, version := range versions {
		versionFields = append(versionFields, version.Version)
	}

	// Sort the retrieved versions using the semver package.
	versionFields, err = semver.SortStrings(1, versionFields)
	if err != nil {
		return nil, err
	}

	patchedIndex := -1
	for i, version := range versionFields {
		if version == dependencyVersion {
			patchedIndex = i
			break
		}
	}

	// If the patched version is found, exclude it and all versions before it.
	if patchedIndex != -1 {
		versionFields = versionFields[patchedIndex+1:]
	}

	// Filter out pre-release versions.
	var filteredVersions []string
	for _, version := range versionFields {
		if !strings.Contains(version, "-") {
			filteredVersions = append(filteredVersions, version)
		}
	}
	versionFields = filteredVersions

	return versionFields, nil
}

func (patcher Patcher) GetNVDVulnerabilities(dependencyName string, dependencyVersion string) (int, []knowledge.NVDItem, error) {
	vulnerabilities := []knowledge.NVDItem{}

	ctx := context.Background()

	// TODO avoid SQL injection
	rows, err := patcher.Knowledge.QueryContext(ctx, `
		WITH preselect AS(SELECT *, jsonb_path_query("affectedFlattened", '$[*].criteriaDict.product ?(@=="`+dependencyName+`")')
		FROM nvd)

		SELECT DISTINCT id, nvd_id, "sourceIdentifier", published, "lastModified", "vulnStatus", descriptions, metrics, weaknesses, configurations, "affectedFlattened", affected, "references"
		FROM preselect
		WHERE "vulnStatus" = 'Analyzed' OR "vulnStatus" = 'Modified'
	`)
	if err != nil {
		panic(err)
	}

	err = patcher.Knowledge.ScanRows(ctx, rows, &vulnerabilities)

	if err != nil {
		panic(err)
	}

	vulnerabilityCount := 0
	semver, err := semver.ParseSemver(dependencyVersion)
	vulnerabilitiesAffectingVersion := []knowledge.NVDItem{}

	for _, vulnerability := range vulnerabilities {
		affectedUniform := nvdMatcher.NormalizeAffectedVersions(dependencyName, vulnerability.Affected, patcher.Knowledge)
		if err != nil {
			continue
		}
		matches, _ := matcher.MatchRange(affectedUniform, semver)
		if matches {
			vulnerabilityCount++
			vulnerabilitiesAffectingVersion = append(vulnerabilitiesAffectingVersion, vulnerability)
			continue
		}
		matches, _ = matcher.MatchExact(affectedUniform, semver)
		if matches {
			vulnerabilityCount++
			vulnerabilitiesAffectingVersion = append(vulnerabilitiesAffectingVersion, vulnerability)
			continue
		}
		matches, _ = matcher.MatchUniversal(affectedUniform, semver)
		if matches {
			vulnerabilityCount++
			vulnerabilitiesAffectingVersion = append(vulnerabilitiesAffectingVersion, vulnerability)
			continue
		}
	}

	return vulnerabilityCount, vulnerabilitiesAffectingVersion, nil
}
