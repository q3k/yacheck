package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"golang.org/x/crypto/nacl/secretbox"
	"k8s.io/klog/v2"
)

// Sessions is a simple 'session' data manager. It stores a serialized Session
// structure in the users' cookies, encrypted and signed using a secret key.
type Sessions struct {
	Secret string
}

// Session is confidential data stored in a user's cookie.
type Session struct {
	Username      string `json:"username"`
	OAuthState    string `json:"oauth_state"`
	OAuthVerifier string `json:"oauth_verifier"`
}

func (s *Sessions) key() [32]byte {
	return sha256.Sum256([]byte(s.Secret))
}

// Get retrives the Session stored in a user's cookies, or nil if not present
// (or invalid).
func (s *Sessions) Get(r *http.Request) *Session {
	secretKey := s.key()

	cookies := r.Cookies()
	for _, cookie := range cookies {
		if cookie.Name != "session2" {
			continue
		}
		encrypted, err := base64.URLEncoding.DecodeString(cookie.Value)
		if err != nil {
			continue
		}
		if len(encrypted) < 24 {
			continue
		}
		var decryptNonce [24]byte
		copy(decryptNonce[:], encrypted[:24])
		decrypted, ok := secretbox.Open(nil, encrypted[24:], &decryptNonce, &secretKey)
		if !ok {
			continue
		}

		var res Session
		if err := json.Unmarshal(decrypted, &res); err != nil {
			continue
		}
		return &res
	}
	return nil
}

// Set saves the given Session into the user's cookies.
func (s *Sessions) Set(w http.ResponseWriter, data *Session) {
	secretKey := s.key()

	decrypted, err := json.Marshal(data)
	if err != nil {
		klog.Errorf("failed to marshal session: %v", err)
		return
	}
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		klog.Errorf("failed to generate nonce: %v", err)
		return
	}
	encrypted := secretbox.Seal(nonce[:], decrypted, &nonce, &secretKey)
	http.SetCookie(w, &http.Cookie{
		Name:     "session2",
		Value:    base64.URLEncoding.EncodeToString(encrypted),
		Secure:   strings.HasPrefix(flagPublicAddress, "https://"),
		HttpOnly: true,
		Path:     "/",
	})
}
