package oauth2provider_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"strings"
	"testing"
)

const (
	libraryPath = "authelia.com/provider/oauth2"
	adapterPath = "github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider/authelia"
)

// TestOAuth2LibraryIsImportedOnlyByItsAdapter keeps the third-party OAuth 2.0
// library behind the adapter. It looks at the imports each package declares
// itself, test files included - not at transitive dependencies, which every
// consumer of the adapter legitimately has.
func TestOAuth2LibraryIsImportedOnlyByItsAdapter(t *testing.T) {
	root, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}").Output()
	if err != nil {
		t.Fatalf("locate module root: %v", err)
	}

	list := exec.Command("go", "list", "-json=ImportPath,Imports,TestImports,XTestImports", "./...")
	list.Dir = strings.TrimSpace(string(root))

	var stderr bytes.Buffer
	list.Stderr = &stderr

	out, err := list.Output()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, stderr.String())
	}

	type pkg struct {
		ImportPath   string
		Imports      []string
		TestImports  []string
		XTestImports []string
	}

	var checked int

	for decoder := json.NewDecoder(bytes.NewReader(out)); ; {
		var p pkg

		if err = decoder.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatalf("decode go list output: %v", err)
		}

		checked++

		if p.ImportPath == adapterPath {
			continue
		}

		for _, imported := range append(append(p.Imports, p.TestImports...), p.XTestImports...) {
			if imported == libraryPath || strings.HasPrefix(imported, libraryPath+"/") {
				t.Errorf("%s imports %s; only %s may", p.ImportPath, imported, adapterPath)
			}
		}
	}

	if checked == 0 {
		t.Fatal("go list reported no packages, so nothing was checked")
	}
}
