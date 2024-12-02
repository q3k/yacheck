package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"k8s.io/klog/v2"
)

// KeaLeaseFile provides Leases by parsing a Key DHCPv4 server leasefile.
type KeaLeaseFile struct {
	// paths to lease files.
	paths []string
}

// Lease is a DHCPv4 server lease. It might or might not be currently active.
type Lease struct {
	IPAddress  net.IP
	MACAddress net.HardwareAddr
	Expires    time.Time
	Hostname   string
}

func getField(parts []string, ix int) string {
	if ix >= len(parts) {
		return ""
	}
	return parts[ix]
}

func (k *KeaLeaseFile) leases(path string) ([]*Lease, error) {
	// Use a map to accumulate result, deduplicating by MAC address.
	resMap := make(map[string]*Lease)

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("could not open leasefile: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	// Not sure if the DHCP lease file format has stable column order, so let's
	// look things up via the column names.
	//
	// Yes, this is effectively a terrible little CSV parser.
	var fieldMap map[string]int
	needFields := []string{"address", "hwaddr", "expire", "hostname"}
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ",")

		if fieldMap == nil {
			// Parse header.
			fieldMap = make(map[string]int)
			for i, part := range parts {
				fieldMap[part] = i
			}
			for _, f := range needFields {
				if _, ok := fieldMap[f]; !ok {
					return nil, fmt.Errorf("leasefile missing field %q", f)
				}
			}
			continue
		}

		// Parse line.
		address := getField(parts, fieldMap["address"])
		ip := net.ParseIP(address)
		if ip == nil {
			klog.Warningf("Leasefile line %q: invalid address %q", line, address)
			continue
		}
		hwaddr := getField(parts, fieldMap["hwaddr"])
		mac, err := net.ParseMAC(hwaddr)
		if err != nil {
			klog.Warningf("Leasefile line %q: invalid hwaddr %q", line, hwaddr)
		}
		expires := getField(parts, fieldMap["expire"])
		expiresInt, err := strconv.ParseInt(expires, 10, 64)
		if err != nil {
			klog.Warningf("Leasefile lien %q: invalid expire time %q", line, expires)
		}
		expiresT := time.Unix(expiresInt, 0)
		hostname := getField(parts, fieldMap["hostname"])

		l := &Lease{
			IPAddress:  ip,
			MACAddress: mac,
			Expires:    expiresT,
			Hostname:   hostname,
		}
		if existing, ok := resMap[l.MACAddress.String()]; ok {
			if l.Expires.After(existing.Expires) {
				resMap[l.MACAddress.String()] = l
			}
		} else {
			resMap[l.MACAddress.String()] = l
		}
	}

	// Sort and return as list.
	res := make([]*Lease, 0, len(resMap))
	for _, l := range resMap {
		res = append(res, l)
	}
	sort.Slice(res, func(i, j int) bool { return res[i].MACAddress.String() < res[j].MACAddress.String() })
	return res, nil
}

func (k *KeaLeaseFile) Leases() ([]*Lease, error) {
	var res []*Lease
	for _, path := range k.paths {
		leases, err := k.leases(path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
		} else {
			res = append(res, leases...)
		}
	}
	return res, nil
}
