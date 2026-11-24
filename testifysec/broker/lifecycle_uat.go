// jade:ring local

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func shutdownUAT(p policy, directory string) (map[string]any, error) {
	p.ListenSocket = filepath.Join(directory, "shutdown.sock")
	p.Limits.TimeoutSeconds = 30
	config := marshal(p)
	policyHash := hash(config)
	configuration := filepath.Join(directory, "shutdown-policy.json")
	if err := os.WriteFile(configuration, config, 0600); err != nil {
		return nil, err
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	command := exec.Command(executable, "serve", "--config", configuration)
	if err = command.Start(); err != nil {
		return nil, err
	}
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	defer command.Process.Kill()
	engine := newEngine(p.DockerSocket)
	workerName := ""
	defer func() {
		if workerName != "" {
			engine.cleanupOwned(workerName, workerName+"-workspace", policyHash)
		}
	}()
	ready := false
	for i := 0; i < 100; i++ {
		connection, err := net.DialTimeout("unix", p.ListenSocket, 50*time.Millisecond)
		if err == nil {
			connection.Close()
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		return nil, fmt.Errorf("shutdown fixture failed to start")
	}
	response := make(chan error, 1)
	go func() {
		_, err := sendFixture(p.ListenSocket, marshal(executionRequest{Schema: requestSchema, Workspace: p.Workspace.ID, Command: "sleep 25"}))
		response <- err
	}()
	filters := urlQuery(marshal(map[string][]string{"label": {"io.testifysec.hardened.policy=" + policyHash}}))
	query := "/containers/json?all=1&filters=" + filters
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	active := false
	for i := 0; i < 100; i++ {
		var workers []struct {
			ID    string `json:"Id"`
			Names []string
			State string
		}
		if err = engine.call(ctx, "GET", query, nil, &workers); err != nil {
			return nil, err
		}
		if len(workers) == 1 && len(workers[0].Names) == 1 {
			workerName = strings.TrimPrefix(workers[0].Names[0], "/")
			if workers[0].State == "running" {
				active = true
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !active {
		return nil, fmt.Errorf("shutdown fixture did not observe an active worker")
	}
	started := time.Now()
	if err = command.Process.Signal(syscall.SIGTERM); err != nil {
		return nil, err
	}
	select {
	case err = <-waited:
		if err != nil {
			return nil, fmt.Errorf("broker shutdown failed: %w", err)
		}
	case <-time.After(35 * time.Second):
		return nil, fmt.Errorf("broker shutdown exceeded deadline")
	}
	select {
	case <-response:
	case <-time.After(3 * time.Second):
		return nil, fmt.Errorf("active client was not canceled")
	}
	check, cancelCheck := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelCheck()
	var workers []json.RawMessage
	if err = engine.call(check, "GET", query, nil, &workers); err != nil {
		return nil, err
	}
	var volumes struct{ Volumes []json.RawMessage }
	if err = engine.call(check, "GET", "/volumes?filters="+filters, nil, &volumes); err != nil {
		return nil, err
	}
	if len(workers) != 0 || len(volumes.Volumes) != 0 {
		return nil, fmt.Errorf("broker exited before worker/volume cleanup")
	}
	return map[string]any{"passed": true, "observedActiveWorker": true, "remainingWorkers": len(workers), "remainingVolumes": len(volumes.Volumes), "elapsedMilliseconds": time.Since(started).Milliseconds()}, nil
}
