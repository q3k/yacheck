package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"k8s.io/klog/v2"
)

var (
	flagSecretFile        = "checkinator.secret"
	flagListen            = ":8080"
	flagPublicAddress     = "https://at.lab.fa-fo.de/"
	flagLeaseFile         = "/var/lib/kea/dhcp4.leases"
	flagDatabaseFile      = "checkinator.db"
	flagOauthClientID     = ""
	flagOauthClientSecret = ""
	flagOauthAuthURL      = "https://git.fa-fo.de/login/oauth/authorize"
	flagOauthTokenURL     = "https://git.fa-fo.de/login/oauth/access_token"
	flagOauthUserInfoURL  = "https://git.fa-fo.de/login/oauth/userinfo"
	flagAPIUsers          = ""
	flagSpaceName         = "FAFO"
	flagSpaceURL          = "https://fa-fo.de/"
)

type APIUser struct {
	Username string
	Password string
}

// Service is the main server/service object of checkinator.
type Service struct {
	Leases   *KeaLeaseFile
	Database *BoltDatabase
	OAuth2   *oauth2.Config
	Sessions *Sessions

	Authorized []APIUser
}

func main() {
	flag.StringVar(&flagSecretFile, "secret_file", flagSecretFile, "Path to secret file (used to sign/encrypt sessions)")
	flag.StringVar(&flagListen, "listen", flagListen, "Address to bind to for HTTP requests")
	flag.StringVar(&flagPublicAddress, "public_address", flagPublicAddress, "Public address of this instance, used for calculating redircect URLs")
	flag.StringVar(&flagLeaseFile, "lease_file", flagLeaseFile, "Path to Kea DHCP4 lease file")
	flag.StringVar(&flagDatabaseFile, "db_file", flagDatabaseFile, "Path to checkinator database file")
	flag.StringVar(&flagOauthClientID, "oauth_client_id", flagOauthClientID, "OAuth client ID")
	flag.StringVar(&flagOauthClientSecret, "oauth_client_secret", flagOauthClientSecret, "OAuth client secret")
	flag.StringVar(&flagOauthAuthURL, "oauth_auth_url", flagOauthAuthURL, "OAuth authorization URL")
	flag.StringVar(&flagOauthTokenURL, "oauth_token_url", flagOauthTokenURL, "OAuth token URL")
	flag.StringVar(&flagOauthUserInfoURL, "oauth_user_info_url", flagOauthUserInfoURL, "OAuth OIDC User Info URL")
	flag.StringVar(&flagAPIUsers, "api_users", flagAPIUsers, "List of API user:password pairs, comma separated")
	flag.StringVar(&flagSpaceName, "space_name", flagSpaceName, "Name of hackerspace to show in interface")
	flag.StringVar(&flagSpaceURL, "space_url", flagSpaceURL, "URL of hackerspace to show in interface")
	flag.Parse()

	var apiUsers []APIUser
	if flagAPIUsers != "" {
		for _, s := range strings.Split(flagAPIUsers, ",") {
			s = strings.TrimSpace(s)
			parts := strings.Split(s, ":")
			if len(parts) != 2 {
				klog.Exitf("Invalid user:password pair %s", s)
			}
			apiUsers = append(apiUsers, APIUser{
				Username: parts[0],
				Password: parts[1],
			})
		}
	}

	if flagOauthClientID == "" || flagOauthClientSecret == "" {
		klog.Exitf("-oauth_client_id and oauth_client_secret must be set")
	}

	lf := KeaLeaseFile{
		paths: []string{flagLeaseFile, flagLeaseFile + ".2"},
	}

	// Get leases to make sure the user provided a working lease backend.
	_, err := lf.Leases()
	if err != nil {
		klog.Exitf("Could not get leases: %v", err)
	}

	db, err := NewBoltDatabase(flagDatabaseFile)
	if err != nil {
		klog.Exitf("Could not create/use database: %v", err)
	}

	if _, err := os.Stat(flagSecretFile); os.IsNotExist(err) {
		var secret [32]byte
		if _, err := io.ReadFull(rand.Reader, secret[:]); err != nil {
			klog.Exitf("Could not generate secret: %v", err)
		}
		if err := os.WriteFile(flagSecretFile, []byte(hex.EncodeToString(secret[:])), 0600); err != nil {
			klog.Exitf("Could not write secret: %v", err)
		}
		klog.Infof("Generated secret at %s", flagSecretFile)
	}
	secret, err := os.ReadFile(flagSecretFile)
	if err != nil {
		klog.Exitf("Could not read secret: %v", err)
	}

	s := Service{
		Leases:   &lf,
		Database: db,
		OAuth2: &oauth2.Config{
			ClientID:     flagOauthClientID,
			ClientSecret: flagOauthClientSecret,
			Scopes:       []string{},
			Endpoint: oauth2.Endpoint{
				AuthURL:  flagOauthAuthURL,
				TokenURL: flagOauthTokenURL,
			},
			RedirectURL: flagPublicAddress + "oauth/redirect",
		},
		Sessions:   &Sessions{Secret: string(secret)},
		Authorized: apiUsers,
	}

	http.HandleFunc("/{$}", s.viewIndex)
	http.HandleFunc("/api.json", s.viewAPIJSON)
	http.HandleFunc("/manage", s.viewManage)
	http.HandleFunc("/claim", s.viewClaim)
	http.HandleFunc("/unclaim/{mac}", s.viewUnclaim)
	http.HandleFunc("/oauth/login", s.viewOauthLogin)
	http.HandleFunc("/oauth/redirect", s.viewOauthRedirect)

	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt)

	go func() {
		klog.Infof("Listening on %s...", flagListen)
		err := http.ListenAndServe(flagListen, nil)
		if err != nil {
			klog.Exitf("HTTP listener failed: %v", err)
		}
	}()
	<-ctx.Done()
}

func (s *Service) getActiveUsers() ([]string, error) {
	leases, err := s.Leases.Leases()
	if err != nil {
		return nil, fmt.Errorf("could not get leases: %w", err)
	}

	var addrs []net.HardwareAddr
	for _, lease := range leases {
		if lease.Expires.Before(time.Now()) {
			continue
		}
		addrs = append(addrs, lease.MACAddress)
	}

	devices, err := s.Database.GetDevicesForMacAddresses(addrs)
	if err != nil {
		return nil, fmt.Errorf("could not get devices: %w", err)
	}

	userSet := make(map[string]bool)
	for _, device := range devices {
		userSet[device.UserNickname] = true
	}
	var users []string
	for k := range userSet {
		users = append(users, k)
	}
	sort.Strings(users)
	return users, nil
}
