// Package publications persists the desired loopback shares for one Hub.
package publications

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
)

const Version = 1

type Entry struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     uint16 `json:"port"`
}

type file struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

func Load(path string) ([]Entry, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("publications: read: %w", err)
	}
	var value file
	if err := json.Unmarshal(raw, &value); err != nil || value.Version != Version {
		return nil, errors.New("publications: invalid state")
	}
	if err := validate(value.Entries); err != nil {
		return nil, err
	}
	return append([]Entry(nil), value.Entries...), nil
}

func Save(path string, entries []Entry) error {
	if err := validate(entries); err != nil {
		return err
	}
	entries = append([]Entry(nil), entries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	raw, err := json.Marshal(file{Version: Version, Entries: entries})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("publications: create directory: %w", err)
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".publications-")
	if err != nil {
		return fmt.Errorf("publications: create temp: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err = temp.Chmod(0o600); err == nil {
		_, err = temp.Write(raw)
	}
	if err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(tempPath, path)
	}
	if err != nil {
		return fmt.Errorf("publications: atomic save: %w", err)
	}
	directory, err := os.Open(filepath.Dir(path))
	if err == nil {
		err = directory.Sync()
		_ = directory.Close()
	}
	return err
}

func validate(entries []Entry) error {
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if entry.Name == "" || (entry.Protocol != "tcp" && entry.Protocol != "udp") ||
			entry.Port == 0 || (entry.Host != "127.0.0.1" && entry.Host != "::1") {
			return errors.New("publications: invalid entry")
		}
		if entry.Name != "port-"+strconv.Itoa(int(entry.Port))+"-"+entry.Protocol {
			return errors.New("publications: non-canonical share name")
		}
		if _, exists := seen[entry.Name]; exists {
			return errors.New("publications: duplicate share name")
		}
		seen[entry.Name] = struct{}{}
	}
	return nil
}
