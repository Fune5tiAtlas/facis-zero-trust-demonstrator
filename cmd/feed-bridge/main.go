// Command feed-bridge serves the IF-01 feed (/snapshot, /events) from the IF-01 log lines it reads
// on standard input, for example the log streams of the guard and the policy evaluator.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/feedbridge"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8090", "address of the feed API")
	contracts := flag.String("contracts", "docs/contracts", "directory of the IF-01 event schemas")
	flag.Parse()
	bridge, err := feedbridge.New(*contracts)
	if err != nil {
		slog.Error("feed bridge", "reason", "event schemas unavailable")
		os.Exit(1)
	}
	server := &http.Server{Addr: *listen, Handler: bridge, ReadHeaderTimeout: 3 * time.Second}
	go func() {
		in := bufio.NewScanner(os.Stdin)
		in.Buffer(make([]byte, 64*1024), 64*1024)
		skipped := 0
		for in.Scan() {
			if errors.Is(bridge.Ingest(in.Bytes()), feedbridge.ErrNotEvent) {
				skipped++
			}
		}
		slog.Info("feed bridge input ended", "skipped_lines", skipped)
	}()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); _ = server.Close() }()
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("feed bridge", "reason", "listener stopped")
		os.Exit(1)
	}
}
