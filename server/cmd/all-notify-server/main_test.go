package main

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/all-notify/server/internal/auth"
	"github.com/all-notify/server/internal/store"
	"github.com/coder/websocket"
)

func TestCLIKeygenAndTokenLifecycle(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()

	// 1. keygen outputs valid 32-byte base64url key and creates no DB.
	var out, errBuf bytes.Buffer
	if err := run(ctx, []string{"keygen"}, &out, &errBuf); err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	kMasterB64 := strings.TrimSpace(out.String())
	if _, err := auth.ValidateMasterKeyB64(kMasterB64); err != nil {
		t.Fatalf("keygen output invalid: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "all-notify.db")); !os.IsNotExist(err) {
		t.Fatalf("keygen must not touch DB")
	}

	// 2. token create rejects --key/--url and points to /admin or pair create.
	out.Reset()
	errBuf.Reset()
	if err := run(ctx, []string{
		"token", "create",
		"--data-dir", dataDir,
		"--name", "Pixel 9",
		"--platform", "android",
		"--url", "https://notify.example.com/",
		"--key", kMasterB64,
	}, &out, &errBuf); err == nil || !strings.Contains(err.Error(), "/admin") || !strings.Contains(err.Error(), "pair create") {
		t.Fatalf("expected error pointing to /admin and pair create, got: %v", err)
	}

	// 2b. token create works without --key/--url and supports --can-add-devices.
	out.Reset()
	errBuf.Reset()
	if err := run(ctx, []string{
		"token", "create",
		"--data-dir", dataDir,
		"--name", "Pixel 9",
		"--platform", "android",
		"--can-add-devices",
	}, &out, &errBuf); err != nil {
		t.Fatalf("token create failed: %v", err)
	}
	output := out.String()
	var devID, rawToken string
	for _, line := range strings.Split(output, "\n") {
		switch {
		case strings.HasPrefix(line, "Device ID:"):
			devID = strings.TrimSpace(strings.TrimPrefix(line, "Device ID:"))
		case strings.HasPrefix(line, "Token:"):
			rawToken = strings.TrimSpace(strings.TrimPrefix(line, "Token:"))
		}
	}
	if devID == "" || rawToken == "" || !strings.Contains(output, "Can Add Devices: true") {
		t.Fatalf("missing fields in token create output:\n%s", output)
	}

	// 2c. pair create outputs valid pc_ code and does not store raw code in DB.
	out.Reset()
	errBuf.Reset()
	if err := run(ctx, []string{
		"pair", "create",
		"--data-dir", dataDir,
		"--name", "MacBook Pro",
		"--platform", "macos",
	}, &out, &errBuf); err != nil {
		t.Fatalf("pair create failed: %v", err)
	}
	var pairCode string
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.HasPrefix(line, "Pairing Code:") {
			pairCode = strings.TrimSpace(strings.TrimPrefix(line, "Pairing Code:"))
		}
	}
	if !auth.PairingCodePattern.MatchString(pairCode) {
		t.Fatalf("pair create invalid code %q:\n%s", pairCode, out.String())
	}

	// Zero-knowledge check: DB must NOT contain raw token, raw pairing code, or K_master anywhere.
	dbBytes, err := os.ReadFile(filepath.Join(dataDir, "all-notify.db"))
	if err != nil {
		t.Fatalf("read db: %v", err)
	}
	if bytes.Contains(dbBytes, []byte(rawToken)) {
		t.Fatalf("raw token leaked into SQLite database!")
	}
	if bytes.Contains(dbBytes, []byte(pairCode)) {
		t.Fatalf("raw pairing code leaked into SQLite database!")
	}
	if bytes.Contains(dbBytes, []byte(kMasterB64)) {
		t.Fatalf("K_master leaked into SQLite database!")
	}

	// 2d. admin reset-password prints password once.
	out.Reset()
	if err := run(ctx, []string{"admin", "reset-password", "--data-dir", dataDir}, &out, &errBuf); err != nil {
		t.Fatalf("admin reset-password failed: %v", err)
	}
	if !strings.Contains(out.String(), "ADMIN INITIAL PASSWORD") {
		t.Fatalf("expected password output from admin reset-password, got:\n%s", out.String())
	}

	// 3. token create validation failures.
	if err := run(ctx, []string{"token", "create", "--data-dir", dataDir, "--name", "X", "--platform", "ios"}, &out, &errBuf); err == nil {
		t.Fatalf("expected error for unsupported platform")
	}
	if err := run(ctx, []string{"token", "list", "--data-dir", dataDir, "unexpected_extra"}, &out, &errBuf); err == nil {
		t.Fatalf("expected error on unexpected positional arg for token list")
	}

	// 4. token list shows active device.
	out.Reset()
	if err := run(ctx, []string{"token", "list", "--data-dir", dataDir}, &out, &errBuf); err != nil {
		t.Fatalf("token list failed: %v", err)
	}
	if !strings.Contains(out.String(), devID) || !strings.Contains(out.String(), "active") {
		t.Fatalf("unexpected token list output:\n%s", out.String())
	}

	// 5. token revoke marks device revoked.
	out.Reset()
	if err := run(ctx, []string{"token", "revoke", "--data-dir", dataDir, devID}, &out, &errBuf); err != nil {
		t.Fatalf("token revoke failed: %v", err)
	}
	st, err := store.Open(filepath.Join(dataDir, "all-notify.db"))
	if err != nil {
		t.Fatal(err)
	}
	dev, err := st.GetDeviceByID(ctx, devID)
	_ = st.Close()
	if err != nil || dev.RevokedAt == nil {
		t.Fatalf("expected device %s to be revoked: dev=%+v err=%v", devID, dev, err)
	}
	if err := run(ctx, []string{"token", "revoke", "--data-dir", dataDir, devID}, &out, &errBuf); err == nil {
		t.Fatalf("revoking already-revoked device should return error")
	}
}

func TestCLIServeGracefulShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dataDir := t.TempDir()
	var out, errBuf bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"serve", "--addr", "127.0.0.1:18923", "--data-dir", dataDir}, &out, &errBuf)
	}()

	// Poll /healthz until server is listening.
	deadline := time.Now().Add(3 * time.Second)
	var healthy bool
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://127.0.0.1:18923/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				healthy = true
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !healthy {
		cancel()
		t.Fatalf("server did not become healthy; stderr:\n%s", errBuf.String())
	}

	if !strings.Contains(out.String(), "ADMIN INITIAL PASSWORD") {
		t.Fatalf("expected initial admin password on first boot stdout, got: %q", out.String())
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve returned error on shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("serve did not shut down cleanly")
	}

	// Second start on same dataDir must NOT print initial password again.
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	var out2, errBuf2 bytes.Buffer
	done2 := make(chan error, 1)
	go func() {
		done2 <- run(ctx2, []string{"serve", "--addr", "127.0.0.1:18924", "--data-dir", dataDir}, &out2, &errBuf2)
	}()
	deadline = time.Now().Add(3 * time.Second)
	healthy = false
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://127.0.0.1:18924/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				healthy = true
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !healthy {
		cancel2()
		t.Fatalf("second serve did not become healthy; stderr:\n%s", errBuf2.String())
	}
	cancel2()
	<-done2
	if strings.Contains(out2.String(), "ADMIN INITIAL PASSWORD") {
		t.Fatalf("second boot unexpectedly printed initial admin password again: %q", out2.String())
	}
}

func TestCLICrossProcessTokenRevokeAndGracefulShutdown(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "all-notify-server")
	dataDir := filepath.Join(tmpDir, "data")

	// Build the real binary.
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("go build binary: %v\n%s", err, string(out))
	}

	// Mint two devices via separate CLI invocations.
	mint := func(name, platform string) (string, string) {
		t.Helper()
		out, err := exec.Command(binPath, "token", "create",
			"--data-dir", dataDir, "--name", name, "--platform", platform,
		).CombinedOutput()
		if err != nil {
			t.Fatalf("token create %s: %v\n%s", name, err, string(out))
		}
		var id, tok string
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "Device ID:") {
				id = strings.TrimSpace(strings.TrimPrefix(line, "Device ID:"))
			} else if strings.HasPrefix(line, "Token:") {
				tok = strings.TrimSpace(strings.TrimPrefix(line, "Token:"))
			}
		}
		if id == "" || tok == "" {
			t.Fatalf("failed parsing token create output:\n%s", string(out))
		}
		return id, tok
	}

	dev1ID, dev1Tok := mint("Phone 1", "android")
	_, dev2Tok := mint("Mac 1", "macos")

	// Pick an ephemeral free port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	// Start `serve` as an independent OS process.
	srvCmd := exec.Command(binPath, "serve", "--addr", addr, "--data-dir", dataDir)
	var srvErr bytes.Buffer
	srvCmd.Stderr = &srvErr
	if err := srvCmd.Start(); err != nil {
		t.Fatalf("start serve: %v", err)
	}
	t.Cleanup(func() {
		if srvCmd.ProcessState == nil {
			_ = srvCmd.Process.Kill()
			_ = srvCmd.Wait()
		}
	})

	// Wait for /healthz.
	deadline := time.Now().Add(5 * time.Second)
	healthy := false
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + addr + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				healthy = true
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !healthy {
		t.Fatalf("serve process not healthy; stderr:\n%s", srvErr.String())
	}

	dial := func(tok string) (*websocket.Conn, *http.Response, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return websocket.Dial(ctx, "ws://"+addr+"/v1/ws", &websocket.DialOptions{
			HTTPHeader: http.Header{
				"Authorization":        []string{"Bearer " + tok},
				"X-AllNotify-Protocol": []string{"1"},
			},
		})
	}

	// Connect both devices.
	conn1, _, err := dial(dev1Tok)
	if err != nil {
		t.Fatalf("dial dev1: %v", err)
	}
	defer conn1.CloseNow()
	rctx, rcancel := context.WithTimeout(context.Background(), 3*time.Second)
	if _, _, err := conn1.Read(rctx); err != nil {
		rcancel()
		t.Fatalf("read replay_complete dev1: %v", err)
	}
	rcancel()

	conn2, _, err := dial(dev2Tok)
	if err != nil {
		t.Fatalf("dial dev2: %v", err)
	}
	defer conn2.CloseNow()
	rctx2, rcancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	if _, _, err := conn2.Read(rctx2); err != nil {
		rcancel2()
		t.Fatalf("read replay_complete dev2: %v", err)
	}
	rcancel2()

	// Run `token revoke` in a SEPARATE OS process against the live WAL database.
	if out, err := exec.Command(binPath, "token", "revoke", "--data-dir", dataDir, dev1ID).CombinedOutput(); err != nil {
		t.Fatalf("cross-process token revoke: %v\n%s", err, string(out))
	}

	// dev1's live WS connection must disconnect with StatusPolicyViolation within 3s.
	revCtx, revCancel := context.WithTimeout(context.Background(), 3*time.Second)
	_, _, revErr := conn1.Read(revCtx)
	revCancel()
	if status := websocket.CloseStatus(revErr); status != websocket.StatusPolicyViolation {
		t.Fatalf("dev1 close status = %v (err=%v), want StatusPolicyViolation\nstderr:\n%s", status, revErr, srvErr.String())
	}

	// dev1 must NOT be able to reconnect (401).
	if _, resp, err := dial(dev1Tok); err == nil || resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked dev1 reconnect expected 401, got err=%v resp=%v", err, resp)
	}

	// Send SIGTERM to live server -> conn2 must receive StatusGoingAway and serve must exit 0.
	shutReadCh := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _, err := conn2.Read(ctx)
		shutReadCh <- err
	}()

	if err := srvCmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal SIGTERM: %v", err)
	}
	if status := websocket.CloseStatus(<-shutReadCh); status != websocket.StatusGoingAway {
		t.Fatalf("dev2 shutdown close status = %v, want StatusGoingAway", status)
	}
	if err := srvCmd.Wait(); err != nil {
		t.Fatalf("serve exited with error after SIGTERM: %v\nstderr:\n%s", err, srvErr.String())
	}
}
