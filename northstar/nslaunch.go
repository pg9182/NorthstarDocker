package main

import (
	"fmt"
	"os"
)

func main() {
	var err error
	if len(os.Args) == 2 {
		switch os.Args[1] {
		case "run":
			err = nslaunch(false)
		case "download":
			err = nslaunch(true)
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func nslaunch(downloadOnly bool) error {
	return fmt.Errorf("not implemented")
}
