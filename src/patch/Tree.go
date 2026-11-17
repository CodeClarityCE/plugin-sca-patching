package patch

import (
	"slices"

	semver "github.com/CodeClarityCE/utility-node-semver"
)

// cachedRegistry remembers registry answers for one run, since candidates share most of their trees.
type cachedRegistry struct {
	registry     Registry
	versions     map[string][]string
	dependencies map[string]map[string]string
}

func newCachedRegistry(registry Registry) *cachedRegistry {
	return &cachedRegistry{registry: registry, versions: map[string][]string{}, dependencies: map[string]map[string]string{}}
}

func (c *cachedRegistry) Versions(name string) ([]string, error) {
	if versions, ok := c.versions[name]; ok {
		return versions, nil
	}
	versions, err := c.registry.Versions(name)
	if err != nil {
		return nil, err
	}
	c.versions[name] = versions
	return versions, nil
}

func (c *cachedRegistry) Dependencies(name, version string) (map[string]string, error) {
	key := name + "@" + version
	if dependencies, ok := c.dependencies[key]; ok {
		return dependencies, nil
	}
	dependencies, err := c.registry.Dependencies(name, version)
	if err != nil {
		return nil, err
	}
	c.dependencies[key] = dependencies
	return dependencies, nil
}

// resolvedTree is every package version that installing one package version pulls in.
type resolvedTree struct {
	// versions lists each package's versions in the tree (name -> versions, ascending).
	versions map[string][]string
	// unchecked counts the dependency constraints that could not be followed, so their
	// subtrees were not checked: unknown packages, unparsable constraints (git, file, url,
	// npm aliases) and constraints that no known version satisfies.
	unchecked int
}

// resolveTree returns the tree installing name@version pulls in, itself included.
// Each constraint resolves to its highest matching stable version. Dependencies are visited
// in name order, so the same registry always gives the same tree.
func resolveTree(registry Registry, name, version string) (resolvedTree, error) {
	tree := resolvedTree{versions: map[string][]string{}}
	seen := map[string]bool{}
	queue := [][2]string{{name, version}}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		key := current[0] + "@" + current[1]
		if seen[key] {
			continue
		}
		seen[key] = true
		tree.versions[current[0]] = append(tree.versions[current[0]], current[1])

		dependencies, err := registry.Dependencies(current[0], current[1])
		if err != nil {
			return resolvedTree{}, err
		}
		dependencyNames := make([]string, 0, len(dependencies))
		for dependency := range dependencies {
			dependencyNames = append(dependencyNames, dependency)
		}
		slices.Sort(dependencyNames)
		for _, dependency := range dependencyNames {
			constraint, err := semver.ParseConstraint(dependencies[dependency])
			if err != nil {
				tree.unchecked++
				continue
			}
			versions, err := registry.Versions(dependency)
			if err != nil {
				return resolvedTree{}, err
			}
			// MaxSatisfyingStrings gives the first version when none matches, so the match is checked again.
			resolved, err := semver.MaxSatisfyingStrings(versions, constraint, false)
			if len(versions) == 0 || err != nil || !semver.Satisfies(resolved, constraint, false) {
				tree.unchecked++
				continue
			}
			queue = append(queue, [2]string{dependency, resolved.String()})
		}
	}
	for pkg, versions := range tree.versions {
		if sorted, err := semver.SortStrings(1, versions); err == nil {
			tree.versions[pkg] = sorted
		}
	}
	return tree, nil
}

// highestVersions gives the highest version of each package in the tree (name -> version).
func (tree resolvedTree) highestVersions() map[string]string {
	highest := map[string]string{}
	for pkg, versions := range tree.versions {
		highest[pkg] = versions[len(versions)-1]
	}
	return highest
}
