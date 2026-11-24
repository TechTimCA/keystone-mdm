// Package store keeps Keystone's state in a single JSON file.
// It is deliberately simple for v0 (small offices, tens of PCs);
// the interface is small so it can move to SQLite later.
package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Device is one enrolled Windows PC.
type Device struct {
	ID           string            `json:"id"`      // Windows DeviceID from enrollment
	HWDevID      string            `json:"hwDevId"` // hardware ID
	Name         string            `json:"name"`    // computer name
	Manufacturer string            `json:"manufacturer"`
	Model        string            `json:"model"`
	OSVersion    string            `json:"osVersion"`
	EnrolledBy   string            `json:"enrolledBy"` // email/user typed at enrollment
	CertThumb    string            `json:"certThumb"`  // SHA-1 thumbprint of the issued device cert
	EnrolledAt   time.Time         `json:"enrolledAt"`
	LastSeen     time.Time         `json:"lastSeen"`
	Props        map[string]string `json:"props"` // latest value per OMA-URI
}

// Command is one OMA-DM command queued for a device.
type Command struct {
	ID        string    `json:"id"`
	DeviceID  string    `json:"deviceId"`
	Verb      string    `json:"verb"` // Get, Exec, Replace, Add, Delete
	LocURI    string    `json:"locUri"`
	Data      string    `json:"data,omitempty"`
	Format    string    `json:"format,omitempty"` // int, chr, bool, xml...
	Label     string    `json:"label"`            // human description shown in the UI
	Status    string    `json:"status"`           // queued, sent, done, failed
	Code      string    `json:"code,omitempty"`   // OMA-DM status code from the device
	CreatedAt time.Time `json:"createdAt"`
	SentAt    time.Time `json:"sentAt,omitempty"`
	DoneAt    time.Time `json:"doneAt,omitempty"`
}

type state struct {
	Devices  map[string]*Device `json:"devices"`
	Commands []*Command         `json:"commands"`
	Seq      int64              `json:"seq"`
}

// Store is safe for concurrent use.
type Store struct {
	mu   sync.Mutex
	path string
	s    state
}

// Open loads (or creates) the store at path.
func Open(path string) (*Store, error) {
	st := &Store{path: path, s: state{Devices: map[string]*Device{}}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return st, os.MkdirAll(filepath.Dir(path), 0o700)
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &st.s); err != nil {
		return nil, err
	}
	if st.s.Devices == nil {
		st.s.Devices = map[string]*Device{}
	}
	return st, nil
}

func (st *Store) saveLocked() error {
	b, err := json.MarshalIndent(st.s, "", "  ")
	if err != nil {
		return err
	}
	tmp := st.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, st.path)
}

// UpsertDevice creates or updates a device via fn and saves.
func (st *Store) UpsertDevice(id string, fn func(d *Device)) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	d, ok := st.s.Devices[id]
	if !ok {
		d = &Device{ID: id, Props: map[string]string{}}
		st.s.Devices[id] = d
	}
	if d.Props == nil {
		d.Props = map[string]string{}
	}
	fn(d)
	return st.saveLocked()
}

// Device returns a copy of one device.
func (st *Store) Device(id string) (Device, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	d, ok := st.s.Devices[id]
	if !ok {
		return Device{}, false
	}
	return copyDevice(d), true
}

// Devices returns copies of all devices, newest check-in first.
func (st *Store) Devices() []Device {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]Device, 0, len(st.s.Devices))
	for _, d := range st.s.Devices {
		out = append(out, copyDevice(d))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

// DeleteDevice removes a device and its commands.
func (st *Store) DeleteDevice(id string) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	delete(st.s.Devices, id)
	keep := st.s.Commands[:0]
	for _, c := range st.s.Commands {
		if c.DeviceID != id {
			keep = append(keep, c)
		}
	}
	st.s.Commands = keep
	return st.saveLocked()
}

func copyDevice(d *Device) Device {
	c := *d
	c.Props = make(map[string]string, len(d.Props))
	for k, v := range d.Props {
		c.Props[k] = v
	}
	return c
}

// Enqueue adds commands for a device.
func (st *Store) Enqueue(cmds ...Command) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, c := range cmds {
		st.s.Seq++
		c := c
		c.ID = itoa(st.s.Seq)
		c.Status = "queued"
		c.CreatedAt = time.Now().UTC()
		st.s.Commands = append(st.s.Commands, &c)
	}
	return st.saveLocked()
}

// TakeQueued marks up to max queued commands for a device as sent and returns them.
func (st *Store) TakeQueued(deviceID string, max int) ([]Command, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	var out []Command
	for _, c := range st.s.Commands {
		if c.DeviceID == deviceID && c.Status == "queued" {
			c.Status = "sent"
			c.SentAt = time.Now().UTC()
			out = append(out, *c)
			if len(out) == max {
				break
			}
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, st.saveLocked()
}

// Complete records the device's status code for a sent command.
func (st *Store) Complete(id, code string) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, c := range st.s.Commands {
		if c.ID == id && c.Status == "sent" {
			c.Code = code
			c.DoneAt = time.Now().UTC()
			if len(code) > 0 && code[0] == '2' {
				c.Status = "done"
			} else {
				c.Status = "failed"
			}
			return st.saveLocked()
		}
	}
	return nil
}

// CommandsFor returns the latest commands for a device, newest first.
func (st *Store) CommandsFor(deviceID string, limit int) []Command {
	st.mu.Lock()
	defer st.mu.Unlock()
	var out []Command
	for i := len(st.s.Commands) - 1; i >= 0 && len(out) < limit; i-- {
		if c := st.s.Commands[i]; c.DeviceID == deviceID {
			out = append(out, *c)
		}
	}
	return out
}

func itoa(n int64) string {
	b := make([]byte, 0, 20)
	if n == 0 {
		return "0"
	}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
