//go:build ignore

// gen.go refreshes specification/v0.1.0/ in this package from the
// repository's specification/v0.1.0/, file for file. Run it through
// go generate ./internal/schema.
package main

import (
	"io/fs"
	"log"
	"os"
	"path/filepath"
)

const (
	source = "../../../../specification/v0.1.0"
	target = "specification/v0.1.0"
)

func main() {
	if err := os.RemoveAll(target); err != nil {
		log.Fatal(err)
	}
	err := filepath.WalkDir(source, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		dst := filepath.Join(target, rel)
		if d.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, b, 0o644)
	})
	if err != nil {
		log.Fatal(err)
	}
}
