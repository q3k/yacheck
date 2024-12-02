package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
)

//go:embed templates/index.html
var templateIndexString string

//go:embed templates/manage.html
var templateManageString string

var (
	templateIndex  = template.Must(template.New("index").Parse(templateIndexString))
	templateManage = template.Must(template.New("manage").Parse(templateManageString))
)

type JSONTop struct {
	Users []JSONUser `json:"users"`
}

type JSONUser struct {
	Login string `json:"login"`
}

func (s *Service) authorized(username, password string) bool {
	for _, au := range s.Authorized {
		// I'll give you 50€ if you can exploit this non-constant-time
		// comparison in practice. ~q3k
		if au.Username == username && au.Password == password {
			return true
		}
	}
	return false
}

func (s *Service) viewAPIJSON(w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	if ok && s.authorized(username, password) {
		users, err := s.getActiveUsers()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "%v", err)
			return
		}
		res := JSONTop{
			Users: make([]JSONUser, 0, len(users)),
		}
		for _, user := range users {
			res.Users = append(res.Users, JSONUser{
				Login: user,
			})
		}
		json.NewEncoder(w).Encode(&res)
		return
	} else {
		w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}

func (s *Service) viewIndex(w http.ResponseWriter, r *http.Request) {
	session := s.Sessions.Get(r)
	if session == nil || session.Username == "" {
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}

	users, err := s.getActiveUsers()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "%v", err)
		return
	}

	templateIndex.Execute(w, map[string]any{
		"Username":  session.Username,
		"Users":     users,
		"SpaceName": flagSpaceName,
		"SpaceURL":  flagSpaceURL,
	})
}

func (s *Service) viewManage(w http.ResponseWriter, r *http.Request) {
	session := s.Sessions.Get(r)
	if session == nil || session.Username == "" {
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}

	devices, err := s.Database.GetDevicesForUser(session.Username)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Could not get your devices: %v", err)
		return
	}

	templateManage.Execute(w, map[string]any{
		"Username":  session.Username,
		"Devices":   devices,
		"SpaceName": flagSpaceName,
		"SpaceURL":  flagSpaceURL,
	})
}

func (s *Service) viewUnclaim(w http.ResponseWriter, r *http.Request) {
	session := s.Sessions.Get(r)
	if session == nil || session.Username == "" {
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}

	address := r.PathValue("mac")
	hwaddr, err := net.ParseMAC(address)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Invalid MAC address.")
		return
	}
	if err := s.Database.UnclaimDevice(session.Username, hwaddr); err != nil {
		fmt.Fprintf(w, "%v", err)
		return
	}
	http.Redirect(w, r, "/manage", http.StatusFound)

}

// remoteHost returns the host/address part of the remote host connecting to
// this HTTP server.
func (s *Service) remoteHost(r *http.Request) string {
	host := r.Header.Get("X-Forwarded-For")
	if host == "" {
		host, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	return host
}

func (s *Service) viewClaim(w http.ResponseWriter, r *http.Request) {
	session := s.Sessions.Get(r)
	if session == nil || session.Username == "" {
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}

	host := s.remoteHost(r)
	if host == "" {
		fmt.Fprintf(w, "Can't get your IP address / host.")
		return
	}
	hostIP := net.ParseIP(host)
	if hostIP == nil {
		fmt.Fprintf(w, "Could not parse your IP.")
		return
	}

	// Find remote host in leases.
	leases, err := s.Leases.Leases()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Can't get leases: %v", err)
		return
	}
	for _, lease := range leases {
		if lease.IPAddress.Equal(hostIP) {
			// If found, claim.
			if err := s.Database.ClaimDevice(session.Username, lease.MACAddress, lease.Hostname); err != nil {
				fmt.Fprintf(w, "Could not claim device: %v", err)
				return
			}
			http.Redirect(w, r, "/manage", http.StatusFound)
			return
		}
	}
	fmt.Fprintf(w, "You must be present at the lab and be using local DNS to claim this device (detected host: %s).", host)
}
