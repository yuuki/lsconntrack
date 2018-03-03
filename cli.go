package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
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

type portslice []string

func (s *portslice) String() string {
	return fmt.Sprintf("%s", *s)
}

func (s *portslice) Set(value string) error {
	if _, err := strconv.Atoi(value); err != nil {
		return fmt.Errorf("%s is not number", value)
	}
	*s = append(*s, value)
	return nil
}

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
		active, passive           bool
		activePorts, passivePorts portslice
		stdin                     bool
		json                      bool
		ver                       bool
	)
	flags := flag.NewFlagSet("lsconntrack", flag.ContinueOnError)
	flags.SetOutput(c.errStream)
	flags.Usage = func() {
		fmt.Fprint(c.errStream, helpText)
	}
	flags.BoolVar(&active, "a", false, "")
	flags.BoolVar(&active, "active", false, "")
	flags.BoolVar(&passive, "p", false, "")
	flags.BoolVar(&passive, "passive", false, "")
	flags.Var(&activePorts, "aport", "")
	flags.Var(&activePorts, "active-port", "")
	flags.Var(&passivePorts, "pport", "")
	flags.Var(&passivePorts, "passive-port", "")
	flags.BoolVar(&stdin, "stdin", false, "")
	flags.BoolVar(&json, "json", false, "")
	flags.BoolVar(&ver, "version", false, "")
	if err := flags.Parse(args[1:]); err != nil {
		return exitCodeFlagParseError
	}

	if ver {
		fmt.Fprintf(c.errStream, "%s version %s, build %s, date %s \n", name, version, commit, date)
		return exitCodeOK
	}

	var mode conntrack.ConnMode
	if active {
		mode |= conntrack.ConnActive
	}
	if passive {
		mode |= conntrack.ConnPassive
	}
	if !active && !passive {
		mode = conntrack.ConnActive | conntrack.ConnPassive
	}

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

	if mode&conntrack.ConnPassive != 0 && len(passivePorts) == 0 {
		var err error
		passivePorts, err = conntrack.LocalListeningPorts()
		if err != nil {
			log.Printf("failed to get local listening ports: %v\n", err)
			return exitCodeParseConntrackError
		}
	}

	result, err := conntrack.ParseEntries(r, conntrack.FilterPorts{
		Active:  activePorts,
		Passive: passivePorts,
	})
	if err != nil {
		log.Println(err)
		return exitCodeParseConntrackError
	}
	if json {
		if err := c.PrintStatsJSON(result, mode); err != nil {
			log.Println(err)
			return exitCodePrintError
		}
	} else {
		c.PrintStats(result, mode)
	}

	return exitCodeOK
}

// PrintStats prints the results.
func (c *CLI) PrintStats(connStat conntrack.ConnStatByAddrPort, mode conntrack.ConnMode) {
	// Format in tab-separated columns with a tab stop of 8.
	tw := tabwriter.NewWriter(c.outStream, 0, 8, 0, '\t', 0)
	fmt.Fprintln(tw, "Local Address:Port\t <--> \tPeer Address:Port \tFQDN \tInpkts \tInbytes \tOutpkts \tOutbytes")
	for _, stat := range connStat {
		if stat.Mode&mode == 0 {
			continue
		}
		hostnames, _ := net.LookupAddr(stat.Addr)
		var hostname string
		if len(hostnames) > 0 {
			hostname = hostnames[0]
		}
		fmt.Fprintln(tw, stat.Dump(hostname))
	}
	tw.Flush()
}

// PrintStatsJSON prints the results as json format.
func (c *CLI) PrintStatsJSON(connStat conntrack.ConnStatByAddrPort, mode conntrack.ConnMode) error {
	for key, stat := range connStat {
		if stat.Mode&mode == 0 {
			delete(connStat, key)
		}
	}
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
