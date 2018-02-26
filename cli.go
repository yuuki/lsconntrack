package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"text/tabwriter"

	"github.com/yuuki/lsconntrack/conntrack"
)

const (
	exitCodeOK             = 0
	exitCodeFlagParseError = 10 + iota
	exitCodeArgumentsError
	exitCodeParseConntrackError
)

// CLI is the command line object.
type CLI struct {
	// outStream and errStream are the stdout and stderr
	// to write message from the CLI.
	outStream, errStream io.Writer
}

// Run execute the main process.
// It returns exit code.
func (c *CLI) Run(args []string) int {
	log.SetOutput(c.errStream)

	var (
		activeMode  bool
		passiveMode bool
		stdin       bool
	)
	flags := flag.NewFlagSet("lsconntrack", flag.ContinueOnError)
	flags.SetOutput(c.errStream)
	flags.Usage = func() {
		fmt.Fprint(c.errStream, helpText)
	}
	flags.BoolVar(&activeMode, "a", false, "")
	flags.BoolVar(&activeMode, "active", false, "")
	flags.BoolVar(&passiveMode, "p", false, "")
	flags.BoolVar(&passiveMode, "passive", false, "")
	flags.BoolVar(&stdin, "stdin", false, "")
	if err := flags.Parse(args[1:]); err != nil {
		return exitCodeFlagParseError
	}

	ports := flags.Args()
	if len(ports) == 0 {
		log.Println(c.errStream, "ports required")
		fmt.Fprint(c.errStream, helpText)
		return exitCodeArgumentsError
	}

	var r io.Reader
	if stdin {
		r = os.Stdin
	} else {
		path := conntrack.FindEntryPath()
		if path == "" {
			log.Println("not found conntrack entries path: Please load conntrack module")
			return exitCodeParseConntrackError
		}
		f, err := os.Open(path)
		if err != nil {
			log.Printf("failed to open %v: %v\n", path, err)
			return exitCodeParseConntrackError
		}
		defer f.Close()
		r = f
	}

	var connStat conntrack.ConnStatByAddrPort
	if activeMode {
		var err error
		connStat, err = conntrack.ParseEntries(r, conntrack.ConnActive, ports)
		if err != nil {
			log.Println(err)
			return exitCodeParseConntrackError
		}
	} else if passiveMode {
		var err error
		connStat, err = conntrack.ParseEntries(r, conntrack.ConnPassive, ports)
		if err != nil {
			log.Println(err)
			return exitCodeParseConntrackError
		}
	}

	// Format in tab-separated columns with a tab stop of 8.
	tw := tabwriter.NewWriter(c.outStream, 0, 8, 0, '\t', 0)
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

var helpText = `Usage: lsconntrack [options] port...

  Print aggregated connections between localhost and other hosts

Options:
  --active, -a      print aggregated connections localhost to destination
  --passive, -p     print aggregated connections source to localhost
  --numeric, -n     show numerical addresses instead of trying to determine symbolic host, port names.
  --stdin           input conntrack entries via stdin
  --json            
  --version, -v		print version
  --help, -h        print help
`
