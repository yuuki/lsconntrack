package main

import (
	"fmt"
	"log"
	"os"

	"github.com/yuuki/lsconntrack/conntrack"
)

const (
	exitCodeOK = iota
	exitCodeParseConntrackError
)

// Run execute the main process.
// It returns exit code.
func Run(args []string) int {
	daddrs, err := conntrack.ParseEntries()
	if err != nil {
		log.Println(err)
		return exitCodeParseConntrackError
	}
	for addr, cnt := range daddrs {
		fmt.Printf("%s %d\n", addr, cnt)
	}
	return exitCodeOK
}

func main() {
	os.Exit(Run(os.Args))
}
