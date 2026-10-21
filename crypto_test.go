package secondfactor

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"os"
	"testing"
	"time"
)

func TestRFC6238(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // RFC 6238 public test vector; gitleaks:allow
	for _, v := range []struct {
		at   int64
		code string
	}{{59, "94287082"}, {1111111109, "07081804"}, {1111111111, "14050471"}, {1234567890, "89005924"}, {2000000000, "69279037"}, {20000000000, "65353130"}} {
		c, e := totp.GenerateCodeCustom(secret, time.Unix(v.at, 0), totp.ValidateOpts{Period: 30, Digits: otp.DigitsEight, Algorithm: otp.AlgorithmSHA1})
		if e != nil || c != v.code {
			t.Fatalf("RFC vector %d failed", v.at)
		}
	}
}
func TestMatchStepDriftReplay(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // RFC 6238 public test vector; gitleaks:allow
	now := time.Unix(2000000000, 0)
	step := now.Unix() / 30
	for _, offset := range []int64{-2, -1, 0, 1, 2} {
		c, _ := totp.GenerateCode(secret, time.Unix((step+offset)*30, 0))
		matched, ok := matchStep(secret, c, now, -1)
		if ok != (offset >= -1 && offset <= 1) {
			t.Fatalf("offset %d", offset)
		}
		if ok && matched != step+offset {
			t.Fatal("wrong watermark")
		}
		if ok {
			if _, replayed := matchStep(secret, c, now, matched); replayed {
				t.Fatal("replay accepted")
			}
		}
	}
	for _, c := range []string{"", "12345", "1234567", "１２３４５６", "abcdef", " 12345"} {
		if _, ok := matchStep(secret, c, now, -1); ok {
			t.Fatal("malformed accepted")
		}
	}
}
func TestEncryptionBindingAndRotation(t *testing.T) {
	s := &Service{active: "k1", keys: map[string][]byte{"k1": bytes.Repeat([]byte{1}, 32), "k2": bytes.Repeat([]byte{2}, 32)}}
	raw, e := s.seal("ab", "c", "factor", 1, []byte("secret"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.open("a", "bc", "factor", raw); e == nil {
		t.Fatal("ambiguous binding")
	}
	for _, v := range []struct{ a, b, c string }{{"other", "c", "factor"}, {"ab", "other", "factor"}, {"ab", "c", "pending"}} {
		if _, e = s.open(v.a, v.b, v.c, raw); e == nil {
			t.Fatal("binding accepted")
		}
	}
	var env sealed
	_ = json.Unmarshal(raw, &env)
	env.Data[0] ^= 1
	bad, _ := json.Marshal(env)
	if _, e = s.open("ab", "c", "factor", bad); e == nil {
		t.Fatal("tampering")
	}
	env.Data[0] ^= 1
	env.Version++
	bad, _ = json.Marshal(env)
	if _, e = s.open("ab", "c", "factor", bad); e == nil {
		t.Fatal("version tampering")
	}
	s.active = "k2"
	plain, e := s.open("ab", "c", "factor", raw)
	if e != nil || string(plain) != "secret" {
		t.Fatal("old key unreadable")
	}
	rotated, e := s.seal("ab", "c", "factor", 1, plain)
	if e != nil {
		t.Fatal(e)
	}
	delete(s.keys, "k1")
	if _, e = s.open("ab", "c", "factor", raw); e == nil {
		t.Fatal("missing key accepted")
	}
	if _, e = s.open("ab", "c", "factor", rotated); e != nil {
		t.Fatal(e)
	}
	if bytes.Equal(aad("ab", "c", "p", 1), aad("a", "bc", "p", 1)) {
		t.Fatal("AAD collision")
	}
}
func TestRecoveryCodes(t *testing.T) {
	seen := map[string]bool{}
	for n := 0; n < 100; n++ {
		c, e := recoveryCode()
		if e != nil || len(c) != 39 || seen[c] {
			t.Fatal("code generation")
		}
		seen[c] = true
		v, ok := normalizeRecovery(c)
		if !ok || len(v) != 32 {
			t.Fatal("normalization")
		}
	}
	for _, v := range []string{"IIII-IIII-IIII-IIII-IIII-IIII-IIII-IIII", "", "0-00000000000000000000000000000000"} {
		if _, ok := normalizeRecovery(v); ok {
			t.Fatal("malformed recovery code")
		}
	}
}
func TestStrictJSON(t *testing.T) {
	var v struct {
		A string `json:"a"`
	}
	for _, s := range []string{`{"a":"x","a":"y"}`, `{"b":1}`, `{"a":"x"} {}`, `{`} {
		if StrictJSON([]byte(s), &v) == nil {
			t.Fatal("invalid JSON accepted")
		}
	}
	if StrictJSON([]byte(`{"a":"x"}`), &v) != nil {
		t.Fatal("valid rejected")
	}
}
func TestSharedAssertionVectors(t *testing.T) {
	raw, e := os.ReadFile("testdata/assertion_vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var all struct {
		Valid []struct {
			Name      string          `json:"name"`
			Seed      string          `json:"seed_hex"`
			KeyID     string          `json:"key_id"`
			Body      string          `json:"body_base64"`
			Claims    AssertionClaims `json:"claims"`
			Assertion string          `json:"assertion"`
		}
	}
	if json.Unmarshal(raw, &all) != nil {
		t.Fatal("invalid fixtures")
	}
	for _, v := range all.Valid {
		seed, _ := hex.DecodeString(v.Seed)
		body, _ := base64.StdEncoding.DecodeString(v.Body)
		if BodyHash(body) != v.Claims.BodyHash {
			t.Fatal("body fixture")
		}
		a, e := SignAssertion(ed25519.NewKeyFromSeed(seed), v.KeyID, v.Claims)
		if e != nil || a != v.Assertion {
			t.Fatalf("fixture %s drifted", v.Name)
		}
	}
}
