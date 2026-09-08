package cmd

import (
	"github.com/3xh4u573d/wmap/internal/model"
	"github.com/3xh4u573d/wmap/internal/parse"
)

func loadScans(paths []string) ([]model.Scan, error) {
	return parse.Files(paths)
}
