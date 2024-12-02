package main

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"

	"go.etcd.io/bbolt"
	"k8s.io/klog/v2"
)

// BoltDatabase stores checkinator data (claimed devices) in a BoltDB instance
// on disk.
type BoltDatabase struct {
	db *bbolt.DB
}

var (
	// Map from hardware ID to serialized Device
	bucketDevices = []byte("devices")
)

// NewBoltDatabase returns a BoltDatabase, creating it at the given path if
// needed.
func NewBoltDatabase(path string) (*BoltDatabase, error) {
	db, err := bbolt.Open(path, 0666, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open DB file: %w", err)
	}

	db.Update(func(tx *bbolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(bucketDevices); err != nil {
			return err
		}
		return nil
	})

	return &BoltDatabase{
		db: db,
	}, nil
}

// Device is the stored per-device data in the database.
type Device struct {
	// MACAddress is the string representation of the MAC address of the device.
	MACAddress string `json:"mac_address"`
	// Hostname is the name of the device as visible to the user in the
	// management panel.
	Hostname string `json:"hostname"`
	// UserNickname is the nickname of the user who manages this device.
	UserNickname string `json:"user_nickname"`
}

func (b *BoltDatabase) getDeviceForMacAddress(devices *bbolt.Bucket, maddr net.HardwareAddr) (*Device, error) {
	deviceBytes := devices.Get([]byte(maddr.String()))
	if deviceBytes == nil {
		return nil, nil
	}
	var device Device
	if err := json.Unmarshal(deviceBytes, &device); err != nil {
		return nil, err
	}
	return &device, nil
}

// GetDevicesForMacAddresses returns a list of devices that match the given MAC
// addresses.
func (b *BoltDatabase) GetDevicesForMacAddresses(macAddresses []net.HardwareAddr) ([]*Device, error) {
	var res []*Device
	err := b.db.View(func(tx *bbolt.Tx) error {
		devices := tx.Bucket(bucketDevices)
		for _, maddr := range macAddresses {
			device, err := b.getDeviceForMacAddress(devices, maddr)
			if err != nil {
				klog.Warningf("Device %q could not be unmarshaled: %v", maddr, err)
				continue
			}
			if device == nil {
				continue
			}
			res = append(res, device)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i].MACAddress < res[j].MACAddress
	})
	return res, nil
}

// GetDevicesForUser returns a list of devices managed by a given user.
func (b *BoltDatabase) GetDevicesForUser(user string) ([]*Device, error) {
	var res []*Device
	err := b.db.View(func(tx *bbolt.Tx) error {
		devices := tx.Bucket(bucketDevices)
		// TODO(q3k): index so that linear scan isn't needed
		cur := devices.Cursor()
		for k, v := cur.First(); k != nil; k, v = cur.Next() {
			var device Device
			if err := json.Unmarshal(v, &device); err != nil {
				klog.Warningf("Device %q could not be unmarshaled: %v", k, err)
				continue
			}
			if device.UserNickname != user {
				continue
			}
			res = append(res, &device)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i].MACAddress < res[j].MACAddress
	})
	return res, nil
}

// ClaimDevice marks a device with a given mac address and hostname as
// managed/claimed by the given user.
//
// If the same user already claimed this device (by MAC address) the hostname
// is updated (upsert semantics).
//
// If some other user already claim this device (by MAC address) an error is
// returned.
func (b *BoltDatabase) ClaimDevice(user string, macAddress net.HardwareAddr, hostname string) error {
	return b.db.Update(func(tx *bbolt.Tx) error {
		devices := tx.Bucket(bucketDevices)
		existing, err := b.getDeviceForMacAddress(devices, macAddress)
		if err != nil {
			return fmt.Errorf("could not unmarshal existing device: %w", err)
		}
		if existing != nil && existing.UserNickname != user {
			return fmt.Errorf("device already claimed")
		}

		v, err := json.Marshal(Device{
			MACAddress:   macAddress.String(),
			Hostname:     hostname,
			UserNickname: user,
		})
		if err != nil {
			return fmt.Errorf("could not marshal device: %v", err)
		}
		return devices.Put([]byte(macAddress.String()), v)
	})
}

// UnclaimDevice releases a device from being managed by the user. If the device
// is managed by some other user, an error is returned.
func (b *BoltDatabase) UnclaimDevice(user string, macAddress net.HardwareAddr) error {
	return b.db.Update(func(tx *bbolt.Tx) error {
		devices := tx.Bucket(bucketDevices)
		device, err := b.getDeviceForMacAddress(devices, macAddress)
		if err != nil {
			return fmt.Errorf("could not unmarshal existing device: %w", err)
		}
		if device != nil && device.UserNickname != user {
			return fmt.Errorf("device does not belong to user")
		}
		return devices.Delete([]byte(macAddress.String()))
	})
}
