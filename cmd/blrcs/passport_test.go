package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/shizukutanaka/blrcs/compliance"
	"github.com/shizukutanaka/blrcs/didresolver"
)

const testClaim = `{"productId":"04012345678901","category":"battery/ev","originCountry":"JP","carbonKgCO2e":48.5,"recyclability":0.82,"phase":"manufacture"}`

func issueForTest(t *testing.T, keyPath string) []byte {
	t.Helper()
	var out, errOut bytes.Buffer
	if code := runIO([]string{"issue", "--key", keyPath, "-"}, strings.NewReader(testClaim), &out, &errOut); code != 0 {
		t.Fatalf("issue exit %d: %s", code, errOut.String())
	}
	return out.Bytes()
}

func TestIssueVerifyRoundTripOffline(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "issuer.key")
	credJSON := issueForTest(t, keyPath)

	if runtime.GOOS != "windows" {
		st, err := os.Stat(keyPath)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("key file mode = %v, want 0600", st.Mode().Perm())
		}
	}

	var cred compliance.Credential
	if err := json.Unmarshal(credJSON, &cred); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(cred.Issuer, "did:key:z6Mk") {
		t.Fatalf("issuer = %q, want did:key", cred.Issuer)
	}
	if cred.Subject.Manufacturer != cred.Issuer {
		t.Errorf("manufacturer = %q, want issuer DID", cred.Subject.Manufacturer)
	}
	// The issuer DID alone is enough for any third party to verify.
	pub, err := didresolver.New().Resolve(context.Background(), cred.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	if err := compliance.Verify(&cred, pub); err != nil {
		t.Fatalf("library verify: %v", err)
	}

	var out, errOut bytes.Buffer
	if code := runIO([]string{"verify", "-"}, bytes.NewReader(credJSON), &out, &errOut); code != 0 {
		t.Fatalf("verify exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "VALID: 04012345678901 issued by "+cred.Issuer) {
		t.Errorf("verify output: %q", out.String())
	}
}

func TestIssueReusesExistingKey(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "issuer.key")
	var a, b compliance.Credential
	if err := json.Unmarshal(issueForTest(t, keyPath), &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(issueForTest(t, keyPath), &b); err != nil {
		t.Fatal(err)
	}
	if a.Issuer != b.Issuer {
		t.Fatalf("issuer changed across runs: %s vs %s", a.Issuer, b.Issuer)
	}
}

func TestVerifyRejectsTamperedCredential(t *testing.T) {
	credJSON := issueForTest(t, filepath.Join(t.TempDir(), "issuer.key"))
	tampered := bytes.Replace(credJSON, []byte(`48.5`), []byte(`1.5`), 1)
	if bytes.Equal(tampered, credJSON) {
		t.Fatal("tamper did not change the credential")
	}
	var out, errOut bytes.Buffer
	if code := runIO([]string{"verify", "-"}, bytes.NewReader(tampered), &out, &errOut); code != 1 {
		t.Fatalf("tampered credential: exit %d, want 1", code)
	}
	if !strings.Contains(errOut.String(), "INVALID") || out.Len() != 0 {
		t.Errorf("stdout=%q stderr=%q", out.String(), errOut.String())
	}
}

func TestVerifyRejectsIssuerSwap(t *testing.T) {
	dir := t.TempDir()
	var a, b map[string]any
	if err := json.Unmarshal(issueForTest(t, filepath.Join(dir, "a.key")), &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(issueForTest(t, filepath.Join(dir, "b.key")), &b); err != nil {
		t.Fatal(err)
	}
	a["issuer"] = b["issuer"]
	swapped, _ := json.Marshal(a)
	var out, errOut bytes.Buffer
	if code := runIO([]string{"verify", "-"}, bytes.NewReader(swapped), &out, &errOut); code != 1 {
		t.Fatalf("issuer-swapped credential: exit %d, want 1", code)
	}
}

func TestIssueRejectsUnknownClaimField(t *testing.T) {
	var out, errOut bytes.Buffer
	claim := `{"productId":"04012345678901","carbonKgC02e":48.5}`
	code := runIO([]string{"issue", "--key", filepath.Join(t.TempDir(), "k"), "-"}, strings.NewReader(claim), &out, &errOut)
	if code != 1 || !strings.Contains(errOut.String(), "carbonKgC02e") {
		t.Fatalf("exit %d stderr=%q", code, errOut.String())
	}
}

func TestIssueRejectsMalformedKeyFile(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "issuer.key")
	if err := os.WriteFile(keyPath, []byte("not-hex\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := runIO([]string{"issue", "--key", keyPath, "-"}, strings.NewReader(testClaim), &out, &errOut); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	b, _ := os.ReadFile(keyPath)
	if string(b) != "not-hex\n" {
		t.Error("malformed key file was overwritten")
	}
}

func TestIssueWithExplicitDID(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "issuer.key")
	var out, errOut bytes.Buffer
	if code := runIO([]string{"issue", "--key", keyPath, "--did", "did:web:factory.example", "-"}, strings.NewReader(testClaim), &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	var cred compliance.Credential
	if err := json.Unmarshal(out.Bytes(), &cred); err != nil {
		t.Fatal(err)
	}
	if cred.Issuer != "did:web:factory.example" {
		t.Fatalf("issuer = %q", cred.Issuer)
	}
	priv, err := loadOrCreateKey(keyPath, &errOut)
	if err != nil {
		t.Fatal(err)
	}
	if err := compliance.Verify(&cred, priv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("verify with local key: %v", err)
	}
}

func TestIssueVerifyUsage(t *testing.T) {
	for _, args := range [][]string{{"issue"}, {"verify"}, {"issue", "a", "b"}} {
		var out, errOut bytes.Buffer
		if code := runIO(args, strings.NewReader(""), &out, &errOut); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
}
