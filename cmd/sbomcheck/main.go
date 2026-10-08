// Command sbomcheck checks a repository SBOM before it is signed and attached to a release: it must be
// valid CycloneDX (the vendored schemas admission uses), and every module that supplies a package to
// the build or the tests of the module in -dir must be in it at the version the build selects. The
// module graph also lists modules that supply no package; those are not required.
//
//	go run ./cmd/sbomcheck -sbom sbom.json -dir <checkout of the release tag>
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/cosignverify"
)

type module struct{ Path, Version string }

// The module of every package built for ./..., tests included, at the selected version (the
// replacement's version when the module is replaced).
const listTemplate = `{{with .Module}}{{if not .Main}}{{.Path}} {{if .Replace}}{{.Replace.Version}}{{else}}{{.Version}}{{end}}{{end}}{{end}}`

func main() {
	sbomPath := flag.String("sbom", "", "CycloneDX JSON SBOM to check")
	dir := flag.String("dir", ".", "directory of the Go module the SBOM describes")
	flag.Parse()
	if *sbomPath == "" {
		fmt.Fprintln(os.Stderr, "usage: sbomcheck -sbom <sbom.json> [-dir <module dir>]")
		os.Exit(2)
	}
	b, err := os.ReadFile(*sbomPath)
	if err != nil {
		fail(err)
	}
	cmd := exec.Command("go", "list", "-deps", "-test", "-f", listTemplate, "./...")
	cmd.Dir, cmd.Stderr = *dir, os.Stderr
	out, err := cmd.Output()
	if err != nil {
		fail(fmt.Errorf("go list: %w", err))
	}
	mods, err := parseModules(strings.NewReader(string(out)))
	if err != nil {
		fail(err)
	}
	missing, err := check(b, mods)
	if err != nil {
		fail(err)
	}
	for _, m := range missing {
		fmt.Fprintf(os.Stderr, "sbomcheck: %s %s is built but not in the SBOM\n", m.Path, m.Version)
	}
	if len(missing) > 0 {
		os.Exit(1)
	}
	fmt.Printf("sbomcheck: valid CycloneDX, all %d modules of the build and tests present\n", len(mods))
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "sbomcheck:", err)
	os.Exit(1)
}

// check validates the SBOM and returns the modules it lacks, sorted by path. Only Go components count.
func check(sbom []byte, mods []module) ([]module, error) {
	if err := cosignverify.ValidateCycloneDX(sbom); err != nil {
		return nil, err
	}
	var doc struct {
		Components []struct{ Name, Version, Purl string } `json:"components"`
	}
	if err := json.Unmarshal(sbom, &doc); err != nil {
		return nil, err
	}
	have := map[module]bool{}
	for _, c := range doc.Components {
		if strings.HasPrefix(c.Purl, "pkg:golang/") {
			have[module{c.Name, c.Version}] = true
		}
	}
	var missing []module
	for _, m := range mods {
		if !have[m] {
			missing = append(missing, m)
		}
	}
	sort.Slice(missing, func(i, j int) bool { return missing[i].Path < missing[j].Path })
	return missing, nil
}

// parseModules reads "path version" lines, skipping blanks and duplicates.
func parseModules(r io.Reader) ([]module, error) {
	seen := map[module]bool{}
	var mods []module
	s := bufio.NewScanner(r)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 2 {
			return nil, fmt.Errorf("malformed module line %q", line)
		}
		if m := (module{f[0], f[1]}); !seen[m] {
			seen[m] = true
			mods = append(mods, m)
		}
	}
	return mods, s.Err()
}
