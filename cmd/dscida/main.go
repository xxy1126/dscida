package main

import (
	"fmt"
	"os"

	"github.com/tmo/dscida/internal/app"
)

func main() {
	if err := app.Run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "dscida: %v\n", err)
		os.Exit(1)
	}
}
