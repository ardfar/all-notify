package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/all-notify/server/internal/api"
	"github.com/all-notify/server/internal/auth"
	"github.com/all-notify/server/internal/blobs"
	"github.com/all-notify/server/internal/hub"
	"github.com/all-notify/server/internal/store"
	"github.com/mdp/qrterminal/v3"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func envString(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envInt64(key string, def int64) (int64, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def, nil
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v <= 0 {
		return 0, fmt.Errorf("invalid %s=%q: must be a positive integer", key, raw)
	}
	return v, nil
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printUsage(stderr)
		return errors.New("missing command")
	}

	switch args[0] {
	case "serve":
		return runServe(ctx, args[1:], stderr)
	case "keygen":
		return runKeygen(args[1:], stdout)
	case "token":
		return runToken(ctx, args[1:], stdout, stderr)
	case "-h", "--help", "help":
		printUsage(stdout)
		return nil
	default:
		printUsage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage: all-notify-server <command> [flags]

Commands:
  serve   Start the HTTP/WebSocket relay server
  keygen  Generate a random 32-byte K_master (base64url; never stored on server)
  token   Manage device tokens (create, list, revoke)`)
}

func runKeygen(args []string, stdout io.Writer) error {
	if len(args) > 0 {
		return errors.New("keygen takes no arguments")
	}
	_, b64, err := auth.GenerateMasterKey()
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, b64)
	return nil
}

func runToken(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: all-notify-server token <create|list|revoke> [flags]")
	}
	switch args[0] {
	case "create":
		return runTokenCreate(ctx, args[1:], stdout, stderr)
	case "list":
		return runTokenList(ctx, args[1:], stdout, stderr)
	case "revoke":
		return runTokenRevoke(ctx, args[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown token subcommand %q (expected create, list, or revoke)", args[0])
	}
}

func openStore(dataDir string) (*store.Store, error) {
	return store.Open(filepath.Join(dataDir, "all-notify.db"))
}

func runTokenCreate(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("token create", flag.ContinueOnError)
	fs.SetOutput(stderr)

	dataDir := fs.String("data-dir", envString("ALLNOTIFY_DATA_DIR", "./data"), "data directory")
	name := fs.String("name", "", "human-readable device name")
	platform := fs.String("platform", "", "device platform (android|macos|windows)")
	serverURL := fs.String("url", "", "public https relay URL (optional; requires --key)")
	masterKey := fs.String("key", "", "base64url K_master for pairing URI/QR (never stored; requires --url)")
	noQR := fs.Bool("no-qr", false, "suppress terminal QR code output")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}

	cleanName := strings.TrimSpace(*name)
	if cleanName == "" {
		return errors.New("--name is required")
	}
	cleanPlatform := strings.ToLower(strings.TrimSpace(*platform))
	switch cleanPlatform {
	case "android", "macos", "windows":
	default:
		return errors.New("--platform must be one of: android, macos, windows")
	}

	hasURL := strings.TrimSpace(*serverURL) != ""
	hasKey := strings.TrimSpace(*masterKey) != ""
	if hasURL != hasKey {
		return errors.New("--url and --key must either both be provided or both omitted")
	}

	devID, err := auth.GenerateDeviceID()
	if err != nil {
		return err
	}
	rawToken, tokenHash, err := auth.GenerateToken()
	if err != nil {
		return err
	}

	var pairingURI string
	if hasURL {
		pairingURI, err = auth.BuildPairingURI(
			strings.TrimSpace(*serverURL),
			rawToken,
			strings.TrimSpace(*masterKey),
			devID,
			cleanName,
		)
		if err != nil {
			return err
		}
	}

	st, err := openStore(*dataDir)
	if err != nil {
		return err
	}
	defer st.Close()

	nowMs := time.Now().UnixMilli()
	if err := st.CreateDevice(ctx, store.Device{
		ID:        devID,
		Name:      cleanName,
		Platform:  cleanPlatform,
		TokenHash: tokenHash,
		CreatedAt: nowMs,
	}); err != nil {
		return err
	}

	fmt.Fprintf(stdout, "Device ID:   %s\n", devID)
	fmt.Fprintf(stdout, "Name:        %s\n", cleanName)
	fmt.Fprintf(stdout, "Platform:    %s\n", cleanPlatform)
	fmt.Fprintf(stdout, "Token:       %s\n", rawToken)
	if pairingURI != "" {
		fmt.Fprintf(stdout, "Pairing URI: %s\n", pairingURI)
		if !*noQR {
			fmt.Fprintln(stdout)
			qrterminal.GenerateHalfBlock(pairingURI, qrterminal.L, stdout)
		}
	}
	return nil
}

func runTokenList(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("token list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data-dir", envString("ALLNOTIFY_DATA_DIR", "./data"), "data directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}

	st, err := openStore(*dataDir)
	if err != nil {
		return err
	}
	defer st.Close()

	devices, err := st.ListDevices(ctx)
	if err != nil {
		return err
	}

	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "DEVICE_ID\tNAME\tPLATFORM\tSTATUS\tLAST_SEQ\tLAST_SEEN\tCREATED_AT")
	for _, d := range devices {
		status := "active"
		if d.RevokedAt != nil {
			status = "revoked"
		}
		lastSeen := "-"
		if d.LastSeen != nil {
			lastSeen = time.UnixMilli(*d.LastSeen).UTC().Format(time.RFC3339)
		}
		createdAt := time.UnixMilli(d.CreatedAt).UTC().Format(time.RFC3339)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			d.ID, d.Name, d.Platform, status, d.LastSeq, lastSeen, createdAt)
	}
	return tw.Flush()
}

func runTokenRevoke(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("token revoke", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data-dir", envString("ALLNOTIFY_DATA_DIR", "./data"), "data directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: all-notify-server token revoke [--data-dir DIR] <device_id>")
	}
	deviceID := strings.TrimSpace(fs.Arg(0))
	if deviceID == "" {
		return errors.New("device_id is required")
	}

	st, err := openStore(*dataDir)
	if err != nil {
		return err
	}
	defer st.Close()

	revoked, err := st.RevokeDevice(ctx, deviceID, time.Now().UnixMilli())
	if err != nil {
		return err
	}
	if !revoked {
		return fmt.Errorf("device %q not found or already revoked", deviceID)
	}
	fmt.Fprintf(stdout, "Revoked device %s\n", deviceID)
	return nil
}

func runServe(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)

	addr := fs.String("addr", envString("ALLNOTIFY_ADDR", ":8080"), "HTTP listen address")
	dataDir := fs.String("data-dir", envString("ALLNOTIFY_DATA_DIR", "./data"), "data directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}

	ttlHours, err := envInt64("ALLNOTIFY_TTL_HOURS", 24)
	if err != nil {
		return err
	}
	maxEventBytes, err := envInt64("ALLNOTIFY_MAX_EVENT_BYTES", 65536)
	if err != nil {
		return err
	}
	maxBlobBytes, err := envInt64("ALLNOTIFY_MAX_BLOB_BYTES", 563200)
	if err != nil {
		return err
	}
	maxTotalBlobMB, err := envInt64("ALLNOTIFY_MAX_TOTAL_BLOB_MB", 256)
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ttl := time.Duration(ttlHours) * time.Hour

	st, err := openStore(*dataDir)
	if err != nil {
		return err
	}
	defer st.Close()

	bm, err := blobs.New(st, blobs.Config{
		Dir:           filepath.Join(*dataDir, "blobs"),
		TTL:           ttl,
		MaxBlobBytes:  maxBlobBytes,
		MaxTotalBytes: maxTotalBlobMB * 1024 * 1024,
		Logger:        logger,
	})
	if err != nil {
		return err
	}

	h := hub.New(st, hub.Config{
		TTL:           ttl,
		MaxEventBytes: int(maxEventBytes),
		Logger:        logger,
	})

	apiServer := api.New(st, h, bm, logger)
	httpServer := &http.Server{
		Addr:              *addr,
		Handler:           apiServer,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", *addr, err)
	}

	bgCtx, bgCancel := context.WithCancel(ctx)
	defer bgCancel()
	go bm.RunReaper(bgCtx, 15*time.Minute)
	go h.RunRevocationWatcher(bgCtx)

	errCh := make(chan error, 1)
	go func() {
		logger.Info("all-notify relay server listening", "addr", ln.Addr().String(), "data_dir", *dataDir)
		if err := httpServer.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		logger.Info("shutting down relay server")
		bgCancel()
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutCtx)
		h.CloseAll(shutCtx)
		return <-errCh
	}
}
