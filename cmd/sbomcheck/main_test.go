package main

import (
	"strings"
	"testing"
)

const sbom = `{"bomFormat":"CycloneDX","specVersion":"1.7","version":1,"components":[
 {"type":"library","name":"golang.org/x/text","version":"v0.42.0","purl":"pkg:golang/golang.org/x/text@v0.42.0"},
 {"type":"library","name":"github.com/cucumber/godog","version":"v0.16.0","purl":"pkg:golang/github.com/cucumber/godog@v0.16.0"},
 {"type":"library","name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0"}]}`

func TestComplete(t *testing.T) {
	mods := []module{{"golang.org/x/text", "v0.42.0"}, {"github.com/cucumber/godog", "v0.16.0"}}
	if missing, err := check([]byte(sbom), mods); err != nil || len(missing) != 0 {
		t.Fatalf("complete SBOM: missing %v, err %v", missing, err)
	}
}

func TestMissingModuleOrVersion(t *testing.T) {
	mods := []module{{"golang.org/x/text", "v0.41.0"}, {"golang.org/x/net", "v0.59.0"}, {"github.com/cucumber/godog", "v0.16.0"}}
	missing, err := check([]byte(sbom), mods)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 2 || missing[0].Path != "golang.org/x/net" || missing[1].Path != "golang.org/x/text" {
		t.Fatalf("want x/net and x/text@v0.41.0 missing, got %v", missing)
	}
}

func TestNotCycloneDX(t *testing.T) {
	if _, err := check([]byte(`{"bomFormat":"SPDX"}`), nil); err == nil {
		t.Fatal("non-CycloneDX accepted")
	}
}

func TestParseModules(t *testing.T) {
	mods, err := parseModules(strings.NewReader("golang.org/x/text v0.42.0\n\ngithub.com/a/b v1.0.0\ngolang.org/x/text v0.42.0\n"))
	if err != nil || len(mods) != 2 {
		t.Fatalf("got %v, %v", mods, err)
	}
	if _, err := parseModules(strings.NewReader("onlypath\n")); err == nil {
		t.Fatal("malformed line accepted")
	}
}
