package main

import (
	"fmt"
	"os"

	"github.com/shadowy-pycoder/go-bitcoin-message-tool/cmd/bmt"
)

func main() {
	if err := bmt.Root(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
