package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	sf "github.com/bwirehq/secondfactor"
	"github.com/bwirehq/secondfactor/integration"
	"github.com/bwirehq/secondfactor/transport"
	"github.com/jackc/pgx/v5/pgxpool"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

type appConfig struct {
	Issuer       string            `json:"issuer"`
	SigningKeys  map[string]string `json:"signing_keys"`
	CallbackURL  string            `json:"callback_url"`
	AllowedCIDRs []string          `json:"allowed_cidrs"`
	CAFile       string            `json:"ca_file"`
}
type config struct {
	DatabaseURLFile string               `json:"database_url_file"`
	Listen          string               `json:"listen"`
	Audience        string               `json:"audience"`
	ActiveKeyID     string               `json:"active_key_id"`
	EncryptionKeys  map[string]string    `json:"encryption_keys"`
	ServiceKeyID    string               `json:"service_key_id"`
	ServiceKeyFile  string               `json:"service_key_file"`
	Applications    map[string]appConfig `json:"applications"`
	TLSCert         string               `json:"tls_cert"`
	TLSKey          string               `json:"tls_key"`
	AllowHTTP       bool                 `json:"allow_http"`
}

func secret(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("secret files must be regular files with mode 0600 or stricter")
	}
	if st.Size() > 16384 {
		return nil, errors.New("secret file too large")
	}
	return os.ReadFile(path)
}
func decoded(path string, n int, private bool) ([]byte, error) {
	var b []byte
	var e error
	if private {
		b, e = secret(path)
	} else {
		b, e = os.ReadFile(path)
	}
	if e != nil {
		return nil, e
	}
	raw, e := base64.StdEncoding.DecodeString(string(bytesTrim(b)))
	if e != nil || len(raw) != n {
		return nil, errors.New("invalid key file")
	}
	return raw, nil
}
func bytesTrim(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
func keygen(dir string) error {
	if e := os.Mkdir(dir, 0700); e != nil {
		return e
	}
	for _, name := range []string{"encryption.key", "service.seed", "application.seed"} {
		b := make([]byte, 32)
		if _, e := rand.Read(b); e != nil {
			return e
		}
		if e := os.WriteFile(filepath.Join(dir, name), []byte(base64.StdEncoding.EncodeToString(b)+"\n"), 0600); e != nil {
			return e
		}
		if name != "encryption.key" {
			p := ed25519.NewKeyFromSeed(b).Public().(ed25519.PublicKey)
			if e := os.WriteFile(filepath.Join(dir, name+".pub"), []byte(base64.StdEncoding.EncodeToString(p)+"\n"), 0644); e != nil {
				return e
			}
		}
	}
	return nil
}
func main() {
	if e := run(); e != nil {
		log.Print("secondfactor: operation failed: ", e)
		os.Exit(1)
	}
}
func run() error {
	command := "serve"
	args := os.Args[1:]
	if len(args) > 0 {
		command = args[0]
		args = args[1:]
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	file := fs.String("config", "config.json", "operator configuration")
	dir := fs.String("dir", "secrets", "new key directory")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if command == "keygen" {
		return keygen(*dir)
	}
	raw, e := os.ReadFile(*file)
	if e != nil {
		return e
	}
	var c config
	if sf.StrictJSON(raw, &c) != nil {
		return errors.New("invalid config")
	}
	if c.Listen == "" || c.Audience == "" || c.ServiceKeyID == "" {
		return errors.New("missing configuration")
	}
	db, e := secret(c.DatabaseURLFile)
	if e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	pool, e := pgxpool.New(ctx, string(bytesTrim(db)))
	if e != nil {
		return errors.New("database configuration invalid")
	}
	defer pool.Close()
	if command == "migrate" {
		return sf.Migrate(ctx, pool)
	}
	keys := map[string][]byte{}
	for id, path := range c.EncryptionKeys {
		k, e := decoded(path, 32, true)
		if e != nil {
			return e
		}
		keys[id] = k
	}
	seed, e := decoded(c.ServiceKeyFile, 32, true)
	if e != nil {
		return e
	}
	callbacks := &integration.Callbacks{KeyID: c.ServiceKeyID, PrivateKey: ed25519.NewKeyFromSeed(seed), Applications: map[string]integration.Destination{}}
	apps := map[string]sf.Application{}
	for id, a := range c.Applications {
		public := map[string]ed25519.PublicKey{}
		for kid, path := range a.SigningKeys {
			k, e := decoded(path, 32, false)
			if e != nil {
				return e
			}
			public[kid] = k
		}
		if len(public) == 0 {
			return errors.New("application signing keys required")
		}
		d := integration.Destination{URL: a.CallbackURL, Keys: public}
		for _, s := range a.AllowedCIDRs {
			p, e := netip.ParsePrefix(s)
			if e != nil {
				return e
			}
			d.AllowedCIDRs = append(d.AllowedCIDRs, p)
		}
		if a.CAFile != "" {
			b, e := os.ReadFile(a.CAFile)
			if e != nil {
				return e
			}
			d.Roots = x509.NewCertPool()
			if !d.Roots.AppendCertsFromPEM(b) {
				return errors.New("invalid callback CA")
			}
		}
		if _, e := integration.SecureHTTP(d); e != nil {
			return e
		}
		callbacks.Applications[id] = d
		apps[id] = sf.Application{Issuer: a.Issuer, Keys: public}
	}
	service, e := sf.New(sf.Config{Pool: pool, Applications: apps, ActiveKeyID: c.ActiveKeyID, Keys: keys, Sessions: callbacks, Recovery: callbacks, Revoker: callbacks})
	if e != nil {
		return e
	}
	if e = service.RegisterApplications(ctx); e != nil {
		return errors.New("apply migrations before starting")
	}
	if e = service.CheckKeyCoverage(ctx); e != nil {
		return errors.New("encryption key coverage unavailable")
	}
	switch command {
	case "rotate":
		for {
			n, e := service.ReencryptBatch(ctx, 100)
			if e != nil {
				return e
			}
			if n == 0 {
				return nil
			}
		}
	case "cleanup":
		return service.Cleanup(ctx)
	case "key-usage":
		v, e := service.KeyUsage(ctx)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(v)
	case "serve":
	default:
		return errors.New("unknown command")
	}
	if !c.AllowHTTP && (c.TLSCert == "" || c.TLSKey == "") {
		return errors.New("TLS required; allow_http is only for a trusted TLS-terminated private network")
	}
	server := &http.Server{Addr: c.Listen, Handler: &transport.Handler{Service: service, Audience: c.Audience}, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 12 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	fmt.Fprintln(os.Stderr, "secondfactor: accepting backend requests")
	if c.AllowHTTP {
		e = server.ListenAndServe()
	} else {
		e = server.ListenAndServeTLS(c.TLSCert, c.TLSKey)
	}
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}
