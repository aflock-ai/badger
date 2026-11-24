// Command plugintool makes and checks connector plugin bundles and signs gateway profiles.
//
//	plugintool keygen -out <prefix>                    writes <prefix>.key (private, encrypted, 0600) and <prefix>.pub
//	plugintool manifest -exe <plugin> -out <file>      runs <plugin> --manifest and writes its tool list;
//	                                                   needs no key: run it where the signing key is not
//	plugintool pack -manifest <file> -digest <sha256> -key <k> -out <dir>
//	                                                   adds the plugin executable's digest
//	                                                   ("sha256:" + sha256sum) and signs; never runs
//	                                                   plugin code
//	plugintool verify -bundle <dir> -pub <p>           checks a bundle and prints its digest
//	plugintool sign -key <k> -in <file>                writes <file>.sig (an administrator signs a profile)
//
// A plugin vendor packs with its own key; the administrator lists that key under the profile's
// signers, pins the printed digest in the connector entry, and signs the profile with the key the
// gateway is started with (--admin-key). Keys are ed25519; public keys base64. A private key file is
// encrypted under a passphrase (keyfile.go) read from --passphrase-file or PLUGINTOOL_PASSPHRASE,
// never from the command line; --insecure-plaintext-key writes or reads the old unencrypted form,
// with a warning.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/aflock-ai/badger/testifysec/connectors/internal/bundle"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "plugintool:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: plugintool keygen|manifest|pack|verify|sign ...")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	out := fs.String("out", "", "output path")
	exe := fs.String("exe", "", "plugin executable")
	digest := fs.String("digest", "", "the plugin executable's sha256, sha256:<hex>")
	key := fs.String("key", "", "private key file")
	pub := fs.String("pub", "", "public key file")
	dir := fs.String("bundle", "", "bundle directory")
	in := fs.String("in", "", "file to sign")
	manifest := fs.String("manifest", "", "the tool manifest written by plugintool manifest")
	passFile := fs.String("passphrase-file", "", "file holding the signing key's passphrase (else PLUGINTOOL_PASSPHRASE)")
	insecure := fs.Bool("insecure-plaintext-key", false, "write or read the signing key unencrypted (warns)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "keygen":
		return keygen(*out, *passFile, *insecure)
	case "manifest":
		return extract(*exe, *out)
	case "pack":
		if *exe != "" {
			return errors.New("pack does not run the plugin: write its tool list with plugintool manifest (without the key), then pack -manifest")
		}
		return pack(*manifest, *digest, *key, *out, *passFile, *insecure)
	case "verify":
		k, err := readPub(*pub)
		if err != nil {
			return err
		}
		m, err := bundle.Load(*dir, k)
		if err != nil {
			return err
		}
		fmt.Printf("%s %s %s\n", m.Name, m.Version, m.Digest)
		return nil
	case "sign":
		k, err := readPriv(*key, *passFile, *insecure)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(*in)
		if err != nil {
			return err
		}
		return os.WriteFile(*in+".sig", bundle.Sign(k, b), 0o644)
	}
	return fmt.Errorf("unknown command %q", args[0])
}

func keygen(prefix, passFile string, insecure bool) error {
	if prefix == "" {
		return errors.New("keygen needs -out")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	var content []byte
	if insecure {
		fmt.Fprintln(os.Stderr, "plugintool: WARNING: writing the signing key unencrypted (--insecure-plaintext-key); whoever copies it can sign any plugin")
		content = []byte(base64.StdEncoding.EncodeToString(priv) + "\n")
	} else {
		pass, err := passphrase(passFile)
		if err != nil {
			return err
		}
		defer zero(pass)
		if content, err = sealKey(priv, pass); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(prefix+".key", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.WriteFile(prefix+".pub", []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644)
}

func readPriv(path, passFile string, insecure bool) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return openKey(b, passFile, insecure)
}

func readPub(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return bundle.ParseKey(strings.TrimSpace(string(b)))
}

// extract runs the plugin's --manifest and writes the tool list it prints. The plugin's code runs
// here, so this step needs no signing key and is meant to run where the key is not (a hostile
// plugin could read any file its user can). It runs a private copy of the bytes it read, so
// replacing the file meanwhile cannot pair one binary's tool list with another binary.
func extract(exe, out string) error {
	if exe == "" || out == "" {
		return errors.New("manifest needs -exe and -out")
	}
	// The file read and the file run are one: a bare name is the file here, never a PATH lookup.
	exe, err := filepath.Abs(exe)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(exe)
	if err != nil {
		return err
	}
	private, err := os.MkdirTemp("", "plugintool-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(private)
	copied := filepath.Join(private, "plugin")
	if err := os.WriteFile(copied, b, 0o500); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, copied, "--manifest")
	cmd.Env = []string{}
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s --manifest: %w", exe, err)
	}
	m, err := bundle.Parse(stdout.Bytes())
	if err != nil {
		return err
	}
	mb, err := jsonIndent(m)
	if err != nil {
		return err
	}
	return os.WriteFile(out, mb, 0o644)
}

// pack builds a bundle from a tool manifest (plugintool manifest) plus the plugin executable's
// digest, and signs it. It runs no plugin code: the key and the plugin never share a process tree.
// The profile pins the same digest; plughost runs the executable only if it matches.
func pack(manifest, digest, keyPath, out, passFile string, insecure bool) error {
	if manifest == "" || keyPath == "" || out == "" || !bundle.ValidDigest(digest) {
		return errors.New("pack needs -manifest, -digest sha256:<hex>, -key and -out")
	}
	b, err := os.ReadFile(manifest)
	if err != nil {
		return err
	}
	m, err := bundle.Parse(b)
	if err != nil {
		return err
	}
	key, err := readPriv(keyPath, passFile, insecure)
	if err != nil {
		return err
	}
	m.Digest = digest
	mb, err := jsonIndent(m)
	if err != nil {
		return err
	}
	if err := os.Mkdir(out, 0o755); err != nil {
		return err
	}
	for name, content := range map[string][]byte{bundle.ManifestFile: mb, bundle.SigFile: bundle.Sign(key, mb)} {
		if err := os.WriteFile(filepath.Join(out, name), content, 0o644); err != nil {
			return err
		}
	}
	fmt.Printf("%s %s %s\n", m.Name, m.Version, m.Digest)
	return nil
}

func jsonIndent(m bundle.Manifest) ([]byte, error) {
	b, err := json.MarshalIndent(m, "", "  ")
	return append(b, '\n'), err
}
