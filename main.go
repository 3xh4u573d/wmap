package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/3xh4u573d/wmap/cmd"
)

func main() {
	err := cmd.Execute()
	if err == nil {
		return
	}
	var coded interface{ Code() int }
	if errors.As(err, &coded) {
		os.Exit(coded.Code())
	}
	fmt.Fprintln(os.Stderr, "wmap: "+err.Error())
	os.Exit(1)
}
