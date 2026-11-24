package main

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
)

// The worker's broker-written mount, read-only at /run/badger and fresh for every execution:
//
//	/run/badger/profile/profile.dsse.json  the exact profile envelope the broker admitted
//	/run/badger/tokens/<name>.token        the caller's connector tokens, copied from
//	                                       <connectorTokenDir>/<caller uid>/<name>.token
//
// The admission verifier and the connector binaries come from the read-only /toolpack mount, at
// /toolpack/badger/admission and /toolpack/badger/connectors/<name> (the toolpack's layout, not
// the broker's). Anything running as the worker's user can read the tokens (CONNECTORS.md, stolen
// token): the broker should be given the narrowest, shortest-lived tokens the service offers.
const (
	runMount        = "/run/badger"
	maxTokens       = 16
	maxTokenBytes   = 64 << 10
	runProfileFile  = "profile.dsse.json"
	runTokensFolder = "tokens"
)

var connectorTokenFile = regexp.MustCompile(`^[a-z0-9-]{1,32}\.token$`)

// provisionRun writes the run directory under scratch for one execution by caller uid. A token
// directory entry that is not a broker-owned, private, singly linked regular file under 64 KiB
// with a connector token name refuses the execution; a caller with no token directory gets none.
func provisionRun(p policy, scratch, envelope string, uid uint32) (_ string, failure error) {
	run := filepath.Join(scratch, "run")
	defer func() {
		if failure != nil { // never leave tokens copied before a refusal
			failure = errors.Join(failure, os.RemoveAll(filepath.Join(run, runTokensFolder)))
		}
	}()
	for _, dir := range []string{run, filepath.Join(run, "profile"), filepath.Join(run, runTokensFolder)} {
		if err := os.Mkdir(dir, 0755); err != nil {
			return "", err
		}
	}
	if envelope != "" {
		if err := os.WriteFile(filepath.Join(run, "profile", runProfileFile), []byte(envelope), 0444); err != nil {
			return "", err
		}
	}
	if p.ConnectorTokenDir == "" {
		return run, nil
	}
	// The parent is checked too: in a directory others can write, another caller's token directory
	// could be renamed to this caller's uid.
	parent, err := secureRoot(p.ConnectorTokenDir)
	if err != nil {
		return "", err
	}
	defer parent.Close()
	unsafe := deny("unsafe_tokens", "Connector token directories must be broker-owned and not writable by others")
	if info, err := parent.Stat("."); err != nil || !ownedPrivate(info, false) {
		return "", unsafe
	}
	name := strconv.FormatUint(uint64(uid), 10)
	if info, err := parent.Lstat(name); errors.Is(err, fs.ErrNotExist) {
		return run, nil
	} else if err != nil || !info.IsDir() {
		return "", unsafe
	}
	root, err := parent.OpenRoot(name)
	if err != nil {
		return "", unsafe
	}
	defer root.Close()
	if info, err := root.Stat("."); err != nil || !ownedPrivate(info, false) {
		return "", unsafe
	}
	directory, err := root.Open(".")
	if err != nil {
		return "", err
	}
	entries, err := directory.ReadDir(maxTokens + 1)
	directory.Close()
	if (err != nil && err != io.EOF) || len(entries) > maxTokens {
		return "", deny("unsafe_tokens", "Too many connector tokens")
	}
	for _, entry := range entries {
		raw, err := readToken(root, entry.Name())
		if err != nil {
			return "", err
		}
		if err = os.WriteFile(filepath.Join(run, runTokensFolder, entry.Name()), raw, 0444); err != nil {
			return "", err
		}
	}
	return run, nil
}

func readToken(root *os.Root, name string) ([]byte, error) {
	refused := deny("unsafe_tokens", "A connector token is not a private broker-owned file with a connector name")
	if !connectorTokenFile.MatchString(name) {
		return nil, refused
	}
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, refused
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !ownedPrivate(info, true) || info.Size() > maxTokenBytes {
		return nil, refused
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxTokenBytes+1))
	if err != nil || len(raw) > maxTokenBytes {
		return nil, refused
	}
	return raw, nil
}
