package cmd

import "fmt"

type exitErr struct{ code int }

func (e exitErr) Error() string { return fmt.Sprintf("exit status %d", e.code) }
func (e exitErr) Code() int     { return e.code }
