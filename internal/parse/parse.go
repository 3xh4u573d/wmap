package parse

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/3xh4u573d/wmap/internal/model"
)

func File(path string) (model.Scan, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return model.Scan{}, err
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".xml":
		return XML(data, path)
	case ".gnmap", ".grep":
		return Gnmap(data, path)
	}

	head := bytes.TrimSpace(data)
	if n := 512; len(head) > n {
		head = head[:n]
	}
	switch {
	case bytes.HasPrefix(head, []byte("<?xml")), bytes.Contains(head, []byte("<nmaprun")):
		return XML(data, path)
	case bytes.HasPrefix(head, []byte("# Nmap")) && bytes.Contains(data, []byte("Host:")):
		return Gnmap(data, path)
	}
	return model.Scan{}, fmt.Errorf("%s: unrecognized nmap output (expected .xml from -oX or .gnmap from -oG)", filepath.Base(path))
}

func Files(paths []string) ([]model.Scan, error) {
	scans := make([]model.Scan, 0, len(paths))
	for _, p := range paths {
		s, err := File(p)
		if err != nil {
			return nil, err
		}
		scans = append(scans, s)
	}
	return scans, nil
}
