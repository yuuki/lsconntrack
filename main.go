package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"text/tabwriter"

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

	var connStat conntrack.ConnStatByAddrPort
	if openMode {
		var err error
		connStat, err = conntrack.ParseEntries(conntrack.ConnActive)
		if err != nil {
			log.Println(err)
			return exitCodeParseConntrackError
		}
	} else if passiveMode {
		var err error
		connStat, err = conntrack.ParseEntries(conntrack.ConnPassive)
		if err != nil {
			log.Println(err)
			return exitCodeParseConntrackError
		}
	}

	// Format in tab-separated columns with a tab stop of 8.
	tw := tabwriter.NewWriter(os.Stdout, 0, 8, 0, '\t', 0)
	for _, stat := range connStat {
		hostnames, _ := net.LookupAddr(stat.Addr)
		var hostname string
		if len(hostnames) > 0 {
			hostname = hostnames[0]
		}
		fmt.Fprintf(tw, "%s:%s\t%s\t%d\t%d\t%d\t%d\n", stat.Addr, stat.Port, hostname, stat.TotalInboundPackets, stat.TotalInboundBytes, stat.TotalOutboundPackets, stat.TotalOutboundBytes)
	}
	tw.Flush()
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
