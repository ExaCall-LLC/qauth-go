package qauth

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// The API clients are tested against the REAL qAuth HTTP server
// (tools/sdk-testserver: qAuth's routes, checks and envelopes over in-memory
// stores), like the JS SDK. It is built from this repository (needs Go), or
// QAUTH_SDK_TESTSERVER points at a built binary.

type seedInfo struct {
	BaseURL    string `json:"baseUrl"`
	OrgKey     string `json:"orgKey"`
	Tenant     string `json:"tenant"`
	Shop       string `json:"shop"`
	Cafe       string `json:"cafe"`
	App        string `json:"app"`
	API        string `json:"api"`
	Permission string `json:"permission"`
	AgentRole  string `json:"agentRole"`
}

var testServer struct {
	once sync.Once
	proc *exec.Cmd
	dir  string
	seed seedInfo
	err  error
}

// liveSeed starts the test server once per test binary and answers its seed.
func liveSeed(t *testing.T) seedInfo {
	t.Helper()
	testServer.once.Do(func() { testServer.seed, testServer.err = startTestServer() })
	if testServer.err != nil {
		t.Fatalf("qAuth test server: %v", testServer.err)
	}
	return testServer.seed
}

func startTestServer() (seedInfo, error) {
	var seed seedInfo
	// a built binary, never `go run` (killing `go run` leaves its child alive)
	bin := os.Getenv("QAUTH_SDK_TESTSERVER")
	if bin == "" {
		dir, err := os.MkdirTemp("", "qauth-go-sdk-")
		if err != nil {
			return seed, err
		}
		testServer.dir = dir
		bin = filepath.Join(dir, "sdk-testserver")
		build := exec.Command("go", "build", "-o", bin, "./tools/sdk-testserver")
		build.Dir = filepath.Join("..", "..")
		build.Stderr = os.Stderr
		if err := build.Run(); err != nil {
			return seed, errors.Join(errors.New("building tools/sdk-testserver"), err)
		}
	}
	cmd := exec.Command(bin, "-addr", "127.0.0.1:0")
	out, err := cmd.StdoutPipe()
	if err != nil {
		return seed, err
	}
	if err := cmd.Start(); err != nil {
		return seed, err
	}
	testServer.proc = cmd
	line := make(chan []byte, 1)
	go func() {
		sc := bufio.NewScanner(out)
		if sc.Scan() {
			line <- append([]byte(nil), sc.Bytes()...)
		}
		close(line)
		for sc.Scan() { // keep draining so the server never blocks on stdout
		}
	}()
	select {
	case b, ok := <-line:
		if !ok {
			return seed, errors.New("the test server exited before printing its seed")
		}
		if err := json.Unmarshal(b, &seed); err != nil {
			return seed, err
		}
	case <-time.After(2 * time.Minute):
		return seed, errors.New("the test server did not start")
	}
	return seed, nil
}

func TestMain(m *testing.M) {
	code := m.Run()
	if testServer.proc != nil && testServer.proc.Process != nil {
		_ = testServer.proc.Process.Kill()
		_ = testServer.proc.Wait()
	}
	if testServer.dir != "" {
		_ = os.RemoveAll(testServer.dir)
	}
	os.Exit(code)
}
