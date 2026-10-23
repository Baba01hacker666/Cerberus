package main

import (
	"fmt"
	"os"

	"github.com/Baba01hacker666/cerberus/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
