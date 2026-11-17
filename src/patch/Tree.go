package patch

import (
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

// resolveTree returns every package version that installing name@version pulls in, itself included.
// Each constraint resolves to its highest matching stable version. Constraints the knowledge base
// cannot resolve (unknown package, git or file URL, no match) end that branch.
func resolveTree(registry Registry, name, version string) (map[string][]string, error) {
	tree := map[string][]string{}
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
		tree[current[0]] = append(tree[current[0]], current[1])

		dependencies, err := registry.Dependencies(current[0], current[1])
		if err != nil {
			return nil, err
		}
		for dependency, constraintString := range dependencies {
			constraint, err := semver.ParseConstraint(constraintString)
			if err != nil {
				continue
			}
			versions, err := registry.Versions(dependency)
			if err != nil {
				return nil, err
			}
			if len(versions) == 0 {
				continue
			}
			resolved, err := semver.MaxSatisfyingStrings(versions, constraint, false)
			if err != nil || resolved.String() == "" {
				continue
			}
			queue = append(queue, [2]string{dependency, resolved.String()})
		}
	}
	return tree, nil
}
