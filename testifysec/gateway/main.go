package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func run() error {
	path := flag.String("config", "", "administrator-provisioned private configuration")
	flag.Parse()
	if *path == "" || flag.NArg() != 0 {
		return fmt.Errorf("usage: hardened-gateway --config /protected/config.json")
	}
	// The provider credential lives in this process's memory: other processes of the same user
	// must not be able to read it (Linux: not dumpable, so no ptrace or /proc/<pid>/mem).
	if err := protectMemory(); err != nil {
		return fmt.Errorf("memory protection unavailable")
	}
	c, err := readConfig(*path)
	if err != nil {
		return fmt.Errorf("invalid protected configuration")
	}
	if err := privateDirectory(filepath.Dir(c.Socket)); err != nil {
		return fmt.Errorf("private socket directory required")
	}
	if err := privateDirectory(filepath.Dir(c.Spool)); err != nil {
		return fmt.Errorf("private spool parent required")
	}
	// Separate process writers must never share a spool. The lock's containing
	// directory is service-owned; neither it nor the spool is mounted in workers.
	lock, err := os.OpenFile(c.Spool+".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("spool already owned")
	}
	g, err := newGateway(c)
	if err != nil {
		return fmt.Errorf("gateway state unavailable")
	}
	if g.identity != nil {
		defer g.identity.Close()
	}
	listener, err := net.Listen("unix", c.Socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	// A precisely mounted per-session socket is the worker's gateway capability.
	// Parent 0700 protects host access; no provider credential enters the worker.
	if err = os.Chmod(c.Socket, 0666); err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	server := &http.Server{Handler: g, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: time.Duration(c.TimeoutSeconds) * time.Second, WriteTimeout: time.Duration(c.TimeoutSeconds+5) * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8192}
	go g.exportLoop(ctx)
	go func() {
		<-ctx.Done()
		shutdown, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_ = server.Shutdown(shutdown)
	}()
	fmt.Println(startLine(g))
	fmt.Println("hardened gateway ready")
	err = server.Serve(listener)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
