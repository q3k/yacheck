package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
)

func (s *Service) viewOauthLogin(w http.ResponseWriter, r *http.Request) {
	var stateBytes [16]byte
	if _, err := io.ReadFull(rand.Reader, stateBytes[:]); err != nil {
		fmt.Fprintf(w, "out of entropy")
		return
	}

	// Generate unqiue state and verifier for CSRF protection.
	state := hex.EncodeToString(stateBytes[:])
	verifier := oauth2.GenerateVerifier()

	// Redirect to provider.
	url := s.OAuth2.AuthCodeURL(state, oauth2.AccessTypeOnline, oauth2.S256ChallengeOption(verifier))
	s.Sessions.Set(w, &Session{
		OAuthState:    state,
		OAuthVerifier: verifier,
	})
	http.Redirect(w, r, url, http.StatusFound)
}

// UserInfo as retrieved from Forgejo.
type UserInfo struct {
	PreferredUsername string `json:"preferred_username"`
}

func (s *Service) viewOauthRedirect(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := s.Sessions.Get(r)
	if session == nil || session.OAuthVerifier == "" || session.OAuthState == "" {
		fmt.Fprintf(w, "no session")
		return
	}

	// Get parameters.
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	// Check state.
	if state != session.OAuthState {
		fmt.Fprintf(w, "invalid session")
		return
	}

	// Exchange OAuth code into token.
	token, err := s.OAuth2.Exchange(ctx, code, oauth2.VerifierOption(session.OAuthVerifier))
	if err != nil {
		fmt.Fprintf(w, "oauth exchange failed")
		return
	}

	// Retrieve user info.
	client := s.OAuth2.Client(ctx, token)
	res, err := client.Get(flagOauthUserInfoURL)
	if err != nil {
		fmt.Fprintf(w, "could not get userinfo")
		return
	}
	defer res.Body.Close()

	var ui UserInfo
	if err := json.NewDecoder(res.Body).Decode(&ui); err != nil {
		fmt.Fprintf(w, "failed to parse userinfo")
		return
	}

	// Save username to session - we are now logged in.
	if ui.PreferredUsername == "" {
		fmt.Fprintf(w, "no username")
		return
	}
	session.Username = ui.PreferredUsername
	session.OAuthState = ""
	session.OAuthVerifier = ""
	s.Sessions.Set(w, session)
	http.Redirect(w, r, "/", http.StatusFound)
}
