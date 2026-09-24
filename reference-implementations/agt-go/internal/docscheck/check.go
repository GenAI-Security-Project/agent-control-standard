package docscheck

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	localLink      = regexp.MustCompile(`\]\(([^)]+)\)`)
	documentedTest = regexp.MustCompile("`((?:[-a-z]+/)*[-a-z]+)\\.(Test\\w+)`")
	testFunc       = regexp.MustCompile(`(?m)^func (Test\w+)\(`)
)

func Check(root string) error {
	documents, err := markdownFiles(root)
	if err != nil {
		return err
	}
	tests := map[string]bool{}
	var problems []string
	for _, document := range documents {
		body, err := os.ReadFile(document)
		if err != nil {
			return err
		}
		problems = append(problems, checkLinks(document, string(body))...)
		for _, match := range documentedTest.FindAllStringSubmatch(string(body), -1) {
			packageName, testName := match[1], match[2]
			key := packageName + "." + testName
			if !tests[key] {
				if err := collectTests(packageDir(root, packageName), packageName, tests); err != nil {
					return err
				}
			}
			if !tests[key] {
				problems = append(problems, fmt.Sprintf("%s names %s, which does not exist", relative(root, document), key))
			}
		}
	}
	conformance, err := os.ReadFile(filepath.Join(root, "docs", "conformance.md"))
	if err != nil {
		return err
	}
	problems = append(problems, checkConformance(string(conformance))...)
	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	return nil
}

func markdownFiles(root string) ([]string, error) {
	var documents []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && (entry.Name() == ".acs" || entry.Name() == "vendor") {
			return filepath.SkipDir
		}
		if !entry.IsDir() && strings.EqualFold(filepath.Ext(path), ".md") {
			documents = append(documents, path)
		}
		return nil
	})
	return documents, err
}

func checkLinks(document, body string) []string {
	var problems []string
	for _, match := range localLink.FindAllStringSubmatch(body, -1) {
		target := strings.TrimSpace(match[1])
		if target == "" || strings.HasPrefix(target, "#") || strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") {
			continue
		}
		target, _, _ = strings.Cut(target, "#")
		if _, err := os.Stat(filepath.Join(filepath.Dir(document), filepath.FromSlash(target))); err != nil {
			problems = append(problems, fmt.Sprintf("%s links to %s, which does not exist", filepath.Base(document), match[1]))
		}
	}
	return problems
}

func checkConformance(body string) []string {
	const header = "| ACS-Core item | Status | Tests | Note |"
	start := strings.Index(body, header)
	if start < 0 {
		return []string{"docs/conformance.md has no ACS-Core table with a Tests column"}
	}
	rows := 0
	items := map[string]bool{}
	var problems []string
	for _, line := range strings.Split(body[start+len(header):], "\n") {
		if !strings.HasPrefix(line, "|") {
			if rows > 0 {
				break
			}
			continue
		}
		columns := strings.Split(line, "|")
		if len(columns) != 6 || strings.TrimSpace(columns[1]) == "---" {
			continue
		}
		item := strings.TrimSpace(columns[1])
		status := strings.TrimSpace(columns[2])
		tests := documentedTest.FindAllStringSubmatch(columns[3], -1)
		if item == "" || status == "" {
			problems = append(problems, "docs/conformance.md contains an incomplete ACS-Core row")
			continue
		}
		if items[item] {
			problems = append(problems, fmt.Sprintf("docs/conformance.md repeats ACS-Core item %q", item))
		}
		items[item] = true
		rows++
		if status != "Not claimed" && len(tests) == 0 {
			problems = append(problems, fmt.Sprintf("docs/conformance.md claims %q without naming a test", item))
		}
	}
	if rows == 0 {
		problems = append(problems, "docs/conformance.md has no ACS-Core rows")
	}
	return problems
}

func packageDir(root, name string) string {
	direct := filepath.Join(root, filepath.FromSlash(name))
	if _, err := os.Stat(direct); err == nil {
		return direct
	}
	found := direct
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err == nil && entry.IsDir() && entry.Name() == name {
			found = path
			return filepath.SkipDir
		}
		return err
	})
	return found
}

func collectTests(dir, prefix string, tests map[string]bool) error {
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return err
	}
	for _, file := range files {
		body, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		for _, match := range testFunc.FindAllSubmatch(body, -1) {
			tests[prefix+"."+string(match[1])] = true
		}
	}
	return nil
}

func relative(root, path string) string {
	name, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(name)
}
