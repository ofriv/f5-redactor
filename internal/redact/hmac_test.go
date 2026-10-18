package redact

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"f5-redactor/internal/config"
)

var testKey = []byte("0123456789abcdef0123456789abcdef") // 32 bytes, tests only

func TestHMACHash(t *testing.T) {
	a := NewActions(defaultSettings)
	a.hashKey = testKey

	mac := hmac.New(sha256.New, testKey)
	mac.Write([]byte("a@b.com"))
	want := "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))

	got := a.Hash("a@b.com")
	if got != want {
		t.Fatalf("Hash = %q, want %q", got, want)
	}
	if got == Hash("a@b.com") {
		t.Error("keyed hash equals the plain SHA-256")
	}
	if !IsHashed(got) {
		t.Error("IsHashed does not recognise HMAC output")
	}
	if again := a.Hash(got); again != got {
		t.Errorf("not idempotent: %q -> %q", got, again)
	}

	// Same value, same output: values can still be compared across logs.
	if a.Hash("a@b.com") != got {
		t.Error("HMAC is not deterministic")
	}

	other := NewActions(defaultSettings)
	other.hashKey = []byte(strings.Repeat("k", 32))
	if other.Hash("a@b.com") == got {
		t.Error("different keys gave the same hash")
	}
}

func TestWithoutKeyHashIsPlainSHA256(t *testing.T) {
	a := NewActions(defaultSettings)
	if got := a.Hash("abc"); got != Hash("abc") {
		t.Errorf("Hash without key = %q, want plain SHA-256 %q", got, Hash("abc"))
	}
}

func TestEngineWithHashKey(t *testing.T) {
	cfg, err := config.Load("../../rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	plain := New(cfg)
	keyed := New(cfg, WithHashKey(testKey))
	if plain.HashAlgorithm() != "sha256" || keyed.HashAlgorithm() != "hmac-sha256" {
		t.Errorf("HashAlgorithm = %q, %q", plain.HashAlgorithm(), keyed.HashAlgorithm())
	}

	in := `{"headers":{"X-Api-Key":"k1"},"body":{"note":"mail a@b.com"}}`
	out, _, err := keyed.RedactLine([]byte(in), nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(out), "hmac-sha256:") != 2 || strings.Contains(string(out), `"sha256:`) || strings.Contains(string(out), " sha256:") {
		t.Errorf("expected two HMAC values and no plain hashes: %s", out)
	}
	// A second run with the same key changes nothing.
	again, _, _ := keyed.RedactLine(out, nil)
	if string(again) != string(out) {
		t.Errorf("not idempotent with a key:\n once %s\ntwice %s", out, again)
	}
}

func TestValidateHashKey(t *testing.T) {
	if err := ValidateHashKey(testKey); err != nil {
		t.Errorf("32-byte key rejected: %v", err)
	}
	err := ValidateHashKey([]byte("short-secret"))
	if err == nil {
		t.Fatal("short key accepted")
	}
	if strings.Contains(err.Error(), "short-secret") {
		t.Errorf("error quotes the key: %v", err)
	}
}
