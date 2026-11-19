package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// fixtureSuffix keeps GitHub from reading fixture manifests as real dependencies.
const fixtureSuffix = ".fixture"

// realManifestNames are the files GitHub's dependency graph picks up.
var realManifestNames = map[string]bool{
	"package.json":        true,
	"package-lock.json":   true,
	"npm-shrinkwrap.json": true,
	"yarn.lock":           true,
	"pnpm-lock.yaml":      true,
}

// TestFixturesHaveNoRealManifestNames fails on any fixture file GitHub would scan.
func TestFixturesHaveNoRealManifestNames(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && realManifestNames[d.Name()] {
			rel, _ := filepath.Rel(dir, path)
			t.Errorf("tests/%s: rename it to %s%s", rel, d.Name(), fixtureSuffix)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
