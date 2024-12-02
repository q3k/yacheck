package main

import (
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestBoltDB(t *testing.T) {
	path := t.TempDir() + "/db"
	db, err := NewBoltDatabase(path)
	if err != nil {
		t.Fatalf("could not create DB: %v", err)
	}

	if err := db.ClaimDevice("jane", net.HardwareAddr([]byte{0, 1, 2, 3, 4, 5}), "stinkpad"); err != nil {
		t.Fatalf("could not claim first device: %v", err)
	}
	if err := db.ClaimDevice("joe", net.HardwareAddr([]byte{0, 1, 2, 3, 4, 6}), "crapbook"); err != nil {
		t.Fatalf("could not claim second device: %v", err)
	}

	devices, err := db.GetDevicesForMacAddresses([]net.HardwareAddr{
		{0, 1, 2, 3, 4, 5},
		{0, 1, 2, 3, 4, 6},
		{0, 1, 2, 3, 4, 7},
	})
	if err != nil {
		t.Fatalf("could not get devices: %v", err)
	}
	if diff := cmp.Diff(devices, []*Device{
		{MACAddress: "00:01:02:03:04:05", UserNickname: "jane", Hostname: "stinkpad"},
		{MACAddress: "00:01:02:03:04:06", UserNickname: "joe", Hostname: "crapbook"},
	}); diff != "" {
		t.Error(diff)
	}

	// Attempt to double claim device.
	if err := db.ClaimDevice("joe", net.HardwareAddr([]byte{0, 1, 2, 3, 4, 5}), "crapbook"); err == nil {
		t.Fatalf("should not be able to double claim device")
	}

	// Update joe's device - this should work.
	if err := db.ClaimDevice("joe", net.HardwareAddr([]byte{0, 1, 2, 3, 4, 6}), "crapbook2"); err != nil {
		t.Fatalf("could not update second device: %v", err)
	}

	devices, err = db.GetDevicesForMacAddresses([]net.HardwareAddr{
		{0, 1, 2, 3, 4, 6},
		{0, 1, 2, 3, 4, 7},
	})
	if err != nil {
		t.Fatalf("could not get devices: %v", err)
	}
	if diff := cmp.Diff(devices, []*Device{
		{MACAddress: "00:01:02:03:04:06", UserNickname: "joe", Hostname: "crapbook2"},
	}); diff != "" {
		t.Error(diff)
	}

	// Unclaim jane's device.
	if err := db.UnclaimDevice("jane", net.HardwareAddr{0, 1, 2, 3, 4, 5}); err != nil {
		t.Fatalf("could not unclaim device: %v", err)
	}

	// Falsely unclaim joe's device as jane's.
	if err := db.UnclaimDevice("jane", net.HardwareAddr{0, 1, 2, 3, 4, 6}); err == nil {
		t.Fatalf("should not be able to unclaim someone else's device")
	}

	devices, err = db.GetDevicesForMacAddresses([]net.HardwareAddr{
		{0, 1, 2, 3, 4, 5},
		{0, 1, 2, 3, 4, 6},
		{0, 1, 2, 3, 4, 7},
	})
	if err != nil {
		t.Fatalf("could not get devices: %v", err)
	}
	if diff := cmp.Diff(devices, []*Device{
		{MACAddress: "00:01:02:03:04:06", UserNickname: "joe", Hostname: "crapbook2"},
	}); diff != "" {
		t.Error(diff)
	}

}
