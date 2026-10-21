package secondfactor

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"strings"
	"time"
)

func token() (string, error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func hash(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }
func aad(app, subject, purpose string, version int64) []byte {
	var b bytes.Buffer
	b.WriteString("secondfactor:aad:v1")
	for _, s := range []string{app, subject, purpose} {
		_ = binary.Write(&b, binary.BigEndian, uint32(len(s)))
		b.WriteString(s)
	}
	_ = binary.Write(&b, binary.BigEndian, version)
	return b.Bytes()
}

type sealed struct {
	Format  int    `json:"format"`
	Key     string `json:"key"`
	Version int64  `json:"version"`
	Nonce   []byte `json:"nonce"`
	Data    []byte `json:"data"`
}

func (s *Service) seal(app, sub, purpose string, version int64, plaintext []byte) ([]byte, error) {
	b, e := aes.NewCipher(s.keys[s.active])
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	n := make([]byte, g.NonceSize())
	if _, e = rand.Read(n); e != nil {
		return nil, e
	}
	return json.Marshal(sealed{1, s.active, version, n, g.Seal(nil, n, plaintext, aad(app, sub, purpose, version))})
}
func (s *Service) open(app, sub, purpose string, raw []byte) ([]byte, error) {
	var v sealed
	if json.Unmarshal(raw, &v) != nil || v.Format != 1 || v.Version < 1 || len(s.keys[v.Key]) != 32 {
		return nil, ErrUnavailable
	}
	b, e := aes.NewCipher(s.keys[v.Key])
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(b)
	if e != nil || len(v.Nonce) != g.NonceSize() {
		return nil, ErrUnavailable
	}
	return g.Open(nil, v.Nonce, v.Data, aad(app, sub, purpose, v.Version))
}

var recoveryEncoding = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

func recoveryCode() (string, error) {
	b := make([]byte, 20)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	s := recoveryEncoding.EncodeToString(b)
	groups := make([]string, 8)
	for j := range groups {
		groups[j] = s[j*4 : j*4+4]
	}
	return strings.Join(groups, "-"), nil
}
func normalizeRecovery(s string) (string, bool) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if len(s) == 39 {
		for j, c := range s {
			if j%5 == 4 && c != '-' {
				return "", false
			}
		}
		s = strings.ReplaceAll(s, "-", "")
	}
	if len(s) != 32 {
		return "", false
	}
	if _, e := recoveryEncoding.DecodeString(s); e != nil {
		return "", false
	}
	return s, true
}
func matchStep(secret, code string, now time.Time, last int64) (int64, bool) {
	if len(code) != 6 {
		return 0, false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	step := now.Unix() / 30
	for _, off := range []int64{0, -1, 1} {
		v := step + off
		if v <= last {
			continue
		}
		ok, e := totp.ValidateCustom(code, secret, time.Unix(v*30, 0), totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if e == nil && ok {
			return v, true
		}
	}
	return 0, false
}
