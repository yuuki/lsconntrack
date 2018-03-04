package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"text/tabwriter"

	"github.com/yuuki/lsconntrack/conntrack"
	"github.com/yuuki/lsconntrack/netutil"
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
		numeric                   bool
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
	flags.BoolVar(&numeric, "n", false, "")
	flags.BoolVar(&numeric, "numeric", false, "")
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

	var mode conntrack.FlowDirection
	if active {
		mode |= conntrack.FlowActive
	}
	if passive {
		mode |= conntrack.FlowPassive
	}
	if !active && !passive {
		mode = conntrack.FlowActive | conntrack.FlowPassive
	}

	var r io.Reader
	if stdin {
		r = os.Stdin
	} else {
		path := netutil.FindConntrackPath()
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

	if mode&conntrack.FlowPassive != 0 && len(passivePorts) == 0 {
		var err error
		passivePorts, err = netutil.LocalListeningPorts()
		if err != nil {
			log.Printf("failed to get local listening ports: %v\n", err)
			return exitCodeParseConntrackError
		}
	}

	flows, err := conntrack.ParseEntries(r, conntrack.FilterPorts{
		Active:  activePorts,
		Passive: passivePorts,
	})
	if err != nil {
		log.Println(err)
		return exitCodeParseConntrackError
	}
	if json {
		if err := c.PrintHostFlowsAsJSON(flows, numeric, mode); err != nil {
			log.Println(err)
			return exitCodePrintError
		}
	} else {
		c.PrintHostFlows(flows, numeric, mode)
	}

	return exitCodeOK
}

// PrintHostFlows prints the host flows.
func (c *CLI) PrintHostFlows(flows conntrack.HostFlows, numeric bool, direction conntrack.FlowDirection) {
	// Format in tab-separated columns with a tab stop of 8.
	tw := tabwriter.NewWriter(c.outStream, 0, 8, 0, '\t', 0)
	fmt.Fprintln(tw, "Local Address:Port\t <--> \tPeer Address:Port \tInpkts \tInbytes \tOutpkts \tOutbytes")
	for _, flow := range flows {
		if flow.HasDirection(direction) {
			continue
		}
		if !numeric {
			flow.ReplaceLookupedName()
		}
		fmt.Fprintln(tw, flow)
	}
	tw.Flush()
}

// PrintHostFlowsAsJSON prints the host flows as json format.
func (c *CLI) PrintHostFlowsAsJSON(flows conntrack.HostFlows, numeric bool, direction conntrack.FlowDirection) error {
	for key, flow := range flows {
		if !numeric {
			flow.ReplaceLookupedName()
		}
		if flow.HasDirection(direction) {
			delete(flows, key)
		}
	}
	b, err := json.Marshal(flows)
	if err != nil {
		return err
	}
	c.outStream.Write(b)
	return nil
}

var helpText = `Usage: lsconntrack [options]

  Print host flows between localhost and other hosts

Options:
  --active, -a              print active-open host flows (from localhost to other host).
  --passive, -p             print passive-open host flows (from other host to localhost).
  --active-port, --aport    output filter by active-open destination ports
  --passive-port, --pport   output filter by localhost listening ports (default: all listening local ports)
  --numeric, -n             show numerical addresses instead of trying to determine symbolic host, port names.
  --stdin                   input conntrack entries via stdin
  --json                    print results as json format
  --version, -v	            print version
  --help, -h                print help
`
