// Command tsa-bundle publishes and activates Rego bundles for the XFSC TSA policy service.
//
//	tsa-bundle pack  -src policies/tsa/facis/guard/1.0 [-data zone.json] -revision R -out DIR
//	tsa-bundle seal  -in DIR -signature sig.b64 -key cosign.pub -out bundle.zip
//	tsa-bundle serve -config /etc/tsa-bundle/config.json
//
// pack writes DIR/policy_bundle.zip and DIR/signing-input.bin (what `cosign sign-blob` signs); seal
// checks the signature and writes the bundle the TSA imports. scripts/supplychain/publish-tsa-bundle.sh
// runs both around cosign. serve is the sidecar in the TSA pod: it keeps the TSA on the bundle Git
// declares, verifying each one before import, serves the trust root to the TSA and exposes only the
// policy's evaluation path.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/ociclient"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/tsabundle"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: tsa-bundle pack|seal|serve [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "pack":
		err = pack(os.Args[2:])
	case "seal":
		err = seal(os.Args[2:])
	case "serve":
		err = serve(os.Args[2:])
	default:
		err = errors.New("unknown command " + os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "tsa-bundle:", err)
		os.Exit(1)
	}
}

func pack(args []string) error {
	fs := flag.NewFlagSet("pack", flag.ExitOnError)
	src := fs.String("src", "", "policy directory {group}/{name}/{version} holding policy.rego and data.json")
	data := fs.String("data", "", "data.json to use instead of the directory's (a zone's configuration)")
	repository := fs.String("repository", "policies", "TSA repository name")
	revision := fs.String("revision", "", "bundle revision, recorded in every decision")
	out := fs.String("out", "", "output directory")
	_ = fs.Parse(args)
	if *src == "" || *out == "" {
		return errors.New("pack needs -src, -revision and -out")
	}
	dir := filepath.Clean(*src)
	c := tsabundle.Coordinates{Repository: *repository, Group: filepath.Base(filepath.Dir(filepath.Dir(dir))),
		Name: filepath.Base(filepath.Dir(dir)), Version: filepath.Base(dir)}
	inner, err := tsabundle.Pack(dir, *data, c, *revision, time.Now())
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, "policy_bundle.zip"), inner, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(*out, "signing-input.bin"), tsabundle.SigningInput(inner), 0o644)
}

func seal(args []string) error {
	fs := flag.NewFlagSet("seal", flag.ExitOnError)
	in := fs.String("in", "", "directory pack wrote")
	sigFile := fs.String("signature", "", "base64 signature of signing-input.bin (cosign sign-blob)")
	keyFile := fs.String("key", "", "public key the signature must verify with")
	out := fs.String("out", "", "bundle file to write")
	_ = fs.Parse(args)
	inner, err := os.ReadFile(filepath.Join(*in, "policy_bundle.zip"))
	if err != nil {
		return err
	}
	b64, err := os.ReadFile(*sigFile)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b64)))
	if err != nil {
		return errors.New("signature is not base64")
	}
	pemData, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	key, err := tsabundle.TrustRoot(pemData)
	if err != nil {
		return err
	}
	outer, err := tsabundle.Seal(inner, sig, key, time.Now())
	if err != nil {
		return err
	}
	return os.WriteFile(*out, outer, 0o644)
}

type config struct {
	TSAURL     string                `json:"tsa_url"`
	TrustRoot  string                `json:"trust_root"`
	Desired    string                `json:"desired"`
	Repository string                `json:"repository"`
	PlainHTTP  []string              `json:"plain_http_registries"`
	PollSecs   int                   `json:"poll_seconds"`
	Policy     tsabundle.Coordinates `json:"policy"`
}

func readJSON(path string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	dec := json.NewDecoder(io.LimitReader(f, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	file := fs.String("config", "/etc/tsa-bundle/config.json", "sidecar configuration")
	_ = fs.Parse(args)
	var cfg config
	if err := readJSON(*file, &cfg); err != nil {
		return err
	}
	tsa, err := url.Parse(cfg.TSAURL)
	if err != nil || tsa.Host == "" || cfg.Repository == "" || cfg.PollSecs < 1 || cfg.Policy.Validate() != nil {
		return errors.New("configuration incomplete")
	}
	pemData, err := os.ReadFile(cfg.TrustRoot)
	if err != nil {
		return err
	}
	key, err := tsabundle.TrustRoot(pemData)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("component", "tsa-bundle")
	client := &http.Client{Timeout: 10 * time.Second}
	s := &tsabundle.Syncer{TSA: strings.TrimRight(cfg.TSAURL, "/"), Policy: cfg.Policy, Key: key, HTTP: client, Log: log,
		Fetch: tsabundle.RegistryFetch(ociclient.New(ociclient.Options{HTTPClient: client, PlainHTTP: cfg.PlainHTTP}), key, cfg.Repository)}

	evaluation := cfg.Policy.EvaluationPath()
	proxy := &httputil.ReverseProxy{Rewrite: func(r *httputil.ProxyRequest) { r.SetURL(tsa) }}
	jwks := tsabundle.JWKS(key)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if s.Active() == "" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /trust-root.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	})
	// Only the policy's evaluation leaves the pod; import, lock, export and admin stay on loopback.
	mux.HandleFunc("POST "+evaluation, func(w http.ResponseWriter, r *http.Request) {
		// Nothing is forwarded while no verified bundle is active, including during a swap.
		if s.Active() == "" {
			http.Error(w, "no verified policy bundle is active", http.StatusServiceUnavailable)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		proxy.ServeHTTP(w, r)
	})
	server := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	failed := make(chan error, 1)
	go func() { failed <- server.ListenAndServe() }()
	go func() {
		for {
			var d tsabundle.Desired
			if err := readJSON(cfg.Desired, &d); err != nil {
				log.Error("desired bundle unreadable", "reason", err.Error(), "active_revision", s.Active())
			} else {
				_ = s.Reconcile(ctx, d)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(cfg.PollSecs) * time.Second):
			}
		}
	}()
	select {
	case <-ctx.Done():
	case err = <-failed:
	}
	shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	_ = server.Shutdown(shutdown)
	return err
}
