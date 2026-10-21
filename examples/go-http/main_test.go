package main

import (
	"context"
	sf "github.com/bwirehq/secondfactor"
	"testing"
	"time"
)

func TestInFlightVerificationCannotResurrectLogout(t *testing.T) {
	original := sf.Session{Subject: "owner", ID: "session", Active: true, AuthenticatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), Generation: 1}
	h := &host{sessions: map[string]record{"session": {Session: original}}, jobs: map[string]int64{}}
	responseReady := make(chan struct{})
	resume := make(chan struct{})
	finished := make(chan bool)
	go func() {
		close(responseReady)
		<-resume
		finished <- h.updateProofs("session", original, sf.Verification{Access: sf.Proof{Token: "late-response"}})
	}()
	<-responseReady
	h.mu.Lock()
	delete(h.sessions, "session")
	h.mu.Unlock()
	close(resume)
	if <-finished {
		t.Fatal("verification restored logged-out session")
	}
	got, _ := h.VerifySession(context.Background(), sf.Identity{Session: "session"})
	if got.Active {
		t.Fatal("primary session resurrected")
	}
}
func TestRevocationCannotBeUndoneByOldVerification(t *testing.T) {
	original := sf.Session{Subject: "owner", ID: "session", Active: true, AuthenticatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), Generation: 0}
	h := &host{sessions: map[string]record{"session": {Session: original}}, jobs: map[string]int64{}}
	if _, e := h.RevokeSessions(context.Background(), sf.RevocationRequest{Subject: "owner", JobID: "job"}); e != nil {
		t.Fatal(e)
	}
	if h.updateProofs("session", original, sf.Verification{}) {
		t.Fatal("revoked session resurrected")
	}
}
