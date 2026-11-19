package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/shizukutanaka/blrcs/compliance"
	"github.com/shizukutanaka/blrcs/didresolver"
	"github.com/shizukutanaka/blrcs/multiformats"
)

// loadOrCreateKey reads a hex Ed25519 seed from path, creating the file
// (mode 0600) with a fresh seed when it does not exist yet. The key never
// leaves the user's machine.
func loadOrCreateKey(path string, stderr io.Writer) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, []byte(hex.EncodeToString(seed)+"\n"), 0o600); err != nil {
			return nil, err
		}
		fmt.Fprintf(stderr, "created issuer key %s (keep it private; back it up)\n", path)
		return ed25519.NewKeyFromSeed(seed), nil
	}
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s: want %d hex-encoded bytes", path, ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func didKey(pub ed25519.PublicKey) string {
	return "did:key:" + multiformats.EncodeEd25519Multikey(pub)
}

func readInput(name string, stdin io.Reader) ([]byte, error) {
	if name == "-" {
		return io.ReadAll(stdin)
	}
	return os.ReadFile(name)
}

func cmdIssue(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("issue", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyPath := fs.String("key", "issuer.key", "Ed25519 seed file (created if missing)")
	did := fs.String("did", "", "issuer DID (default: did:key derived from the key)")
	days := fs.Int("valid-days", 3650, "validity in days (0 = no expiry)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: blrcs issue [--key FILE] [--did DID] [--valid-days N] <claim.json|->")
		return 2
	}
	raw, err := readInput(fs.Arg(0), stdin)
	if err != nil {
		fmt.Fprintln(stderr, "read claim:", err)
		return 1
	}
	var claim compliance.PassportClaim
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&claim); err != nil {
		fmt.Fprintln(stderr, "parse claim:", err)
		return 1
	}
	priv, err := loadOrCreateKey(*keyPath, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "issuer key:", err)
		return 1
	}
	id := *did
	if id == "" {
		id = didKey(priv.Public().(ed25519.PublicKey))
	}
	if claim.Manufacturer == "" {
		claim.Manufacturer = id
	}
	iss, err := compliance.NewIssuerFromKey(id, priv)
	if err != nil {
		fmt.Fprintln(stderr, "issuer:", err)
		return 1
	}
	cred, err := iss.Issue(claim, time.Duration(*days)*24*time.Hour)
	if err != nil {
		fmt.Fprintln(stderr, "issue:", err)
		return 1
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cred); err != nil {
		fmt.Fprintln(stderr, "write:", err)
		return 1
	}
	return 0
}

func cmdVerify(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	timeout := fs.Int("timeout", 10, "DID resolution timeout seconds (did:web only)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: blrcs verify <credential.json|->")
		return 2
	}
	raw, err := readInput(fs.Arg(0), stdin)
	if err != nil {
		fmt.Fprintln(stderr, "read credential:", err)
		return 1
	}
	var cred compliance.Credential
	if err := json.Unmarshal(raw, &cred); err != nil {
		fmt.Fprintln(stderr, "parse credential:", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeout)*time.Second)
	defer cancel()
	keys, err := didresolver.New().ResolveAll(ctx, cred.Issuer)
	if err != nil {
		fmt.Fprintf(stderr, "INVALID: resolve issuer %q: %v\n", cred.Issuer, err)
		return 1
	}
	for _, k := range keys {
		if err = compliance.Verify(&cred, k); err == nil {
			fmt.Fprintf(stdout, "VALID: %s issued by %s\n", cred.Subject.ProductID, cred.Issuer)
			return 0
		}
	}
	fmt.Fprintln(stderr, "INVALID:", err)
	return 1
}
