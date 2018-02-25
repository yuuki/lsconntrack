package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/yuuki/lsconntrack/conntrack"
)

const (
	exitCodeOK = iota
	exitCodeFlagParseError
	exitCodeParseConntrackError
)

// Run execute the main process.
// It returns exit code.
func Run(args []string) int {
	var (
		openMode    bool
		passiveMode bool
	)
	flags := flag.NewFlagSet("lsconntrack", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	flags.Usage = func() {
		fmt.Fprint(os.Stderr, helpText)
	}
	flags.BoolVar(&openMode, "o", false, "")
	flags.BoolVar(&openMode, "open", false, "")
	flags.BoolVar(&passiveMode, "p", false, "")
	flags.BoolVar(&passiveMode, "passive", false, "")
	if err := flags.Parse(args[1:]); err != nil {
		return exitCodeFlagParseError
	}

	if openMode {
		openConnStat, err := conntrack.ParseEntries()
		if err != nil {
			log.Println(err)
			return exitCodeParseConntrackError
		}
		for _, stat := range openConnStat {
			fmt.Printf("%s:%s\t%d\t%d\t%d\t%d\n", stat.Addr, stat.Port, stat.TotalInboundPackets, stat.TotalInboundBytes, stat.TotalOutboundPackets, stat.TotalOutboundBytes)
		}
	} else if passiveMode {
	}
	return exitCodeOK
}

func main() {
	os.Exit(Run(os.Args))
}

var helpText = `Usage: lsconntrack [options] [-]

  Print aggregated connections between localhost and other hosts

Options:
  --open, -o        print aggregated connections localhost to destination
  --passive, -p     print aggregated connections source to localhost
  --numeric, -n     show numerical addresses instead of trying to determine symbolic host, port names.
  --version, -v		print version
  --help, -h        print help
`
