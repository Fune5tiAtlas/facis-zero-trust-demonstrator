package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The TSA gate passes on the chart and fails once the pod template reads the bundle declaration,
// whether through its reference or its revision.
func TestTSAGateRefusesABundleBoundPod(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed")
	}
	root, _ := filepath.Abs("../../..")
	chart := filepath.Join(root, "deployment/helm/tsa-policy")
	if err := checkTSA(root, chart); err != nil {
		t.Fatalf("chart refused: %v", err)
	}
	for name, annotation := range map[string]string{
		"revision": "bundle-revision: {{ .Values.bundle.revision | quote }}",
		"ref":      "bundle-ref: {{ .Values.bundle.ref | quote }}",
	} {
		t.Run(name, func(t *testing.T) {
			copied := filepath.Join(t.TempDir(), "tsa-policy")
			if out, err := exec.Command("cp", "-R", chart, copied).CombinedOutput(); err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			path := filepath.Join(copied, "templates/workload.yaml")
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			anchor := "        checksum/config:"
			if !strings.Contains(string(b), anchor) {
				t.Fatal("annotation anchor missing")
			}
			b = []byte(strings.Replace(string(b), anchor, "        "+annotation+"\n"+anchor, 1))
			if err := os.WriteFile(path, b, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := checkTSA(root, copied); err == nil {
				t.Fatal("a pod annotation bound to the bundle declaration passed the gate")
			}
		})
	}
}
