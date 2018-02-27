package main

import (
	"encoding/json"
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
	exitCodePrintError
	exitCodeUnreachableError
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
		json        bool
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
	flags.BoolVar(&json, "json", false, "")
	if err := flags.Parse(args[1:]); err != nil {
		return exitCodeFlagParseError
	}

	if !activeMode && !passiveMode {
		log.Println("--active or --passive required")
		fmt.Fprint(c.errStream, helpText)
		return exitCodeArgumentsError
	}

	ports := flags.Args()

	var r io.Reader
	if stdin {
		r = os.Stdin
	} else {
		path := conntrack.FindProcPath()
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

	if passiveMode && len(ports) == 0 {
		var err error
		ports, err = conntrack.LocalListeningPorts()
		if err != nil {
			log.Printf("failed to get local listening ports: %v\n", err)
			return exitCodeParseConntrackError
		}
		log.Println(ports)
	}

	entries, err := conntrack.ParseEntries(r, ports)
	if err != nil {
		log.Println(err)
		return exitCodeParseConntrackError
	}
	var result conntrack.ConnStatByAddrPort
	if activeMode {
		result = entries.Active
	} else if passiveMode {
		result = entries.Passive
	} else {
		log.Println("unreachable code")
		return exitCodeUnreachableError
	}
	if json {
		if err := c.PrintStatsJSON(result); err != nil {
			log.Println(err)
			return exitCodePrintError
		}
	} else {
		c.PrintStats(result)
	}

	return exitCodeOK
}

// PrintStats prints the results.
func (c *CLI) PrintStats(connStat conntrack.ConnStatByAddrPort) {
	// Format in tab-separated columns with a tab stop of 8.
	tw := tabwriter.NewWriter(c.outStream, 0, 8, 0, '\t', 0)
	fmt.Fprintln(tw, "RemoteAddress:Port \tFQDN \tInpkts \tInbytes \tOutpkts \tOutbytes")
	for _, stat := range connStat {
		hostnames, _ := net.LookupAddr(stat.Addr)
		var hostname string
		if len(hostnames) > 0 {
			hostname = hostnames[0]
		}
		fmt.Fprintf(tw, "%s:%s\t%s\t%d\t%d\t%d\t%d\n", stat.Addr, stat.Port, hostname, stat.TotalInboundPackets, stat.TotalInboundBytes, stat.TotalOutboundPackets, stat.TotalOutboundBytes)
	}
	tw.Flush()
}

// PrintStatsJSON prints the results as json format.
func (c *CLI) PrintStatsJSON(connStat conntrack.ConnStatByAddrPort) error {
	b, err := json.Marshal(connStat)
	if err != nil {
		return err
	}
	c.outStream.Write(b)
	return nil
}

var helpText = `Usage: lsconntrack [options] [port...]

  Print aggregated connections between localhost and other hosts

Options:
  --active, -a      print aggregated connections localhost to destination
  --passive, -p     print aggregated connections source to localhost (adopt listening ports as default)
  --numeric, -n     show numerical addresses instead of trying to determine symbolic host, port names.
  --stdin           input conntrack entries via stdin
  --json            print results as json format
  --version, -v		print version
  --help, -h        print help
`
