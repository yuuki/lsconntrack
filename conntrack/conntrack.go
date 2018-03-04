package conntrack

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/yuuki/lsconntrack/netutil"
)

// FlowDirection are bitmask that represents both Active or Passive.
type FlowDirection int

const (
	// FlowUnknown are unknown flow.
	FlowUnknown FlowDirection = 1 << iota
	// FlowActive are 'active open'.
	FlowActive
	// FlowPassive are 'passive open'
	FlowPassive
)

// MarshalJSON returns human readable `mode` format.
func (c FlowDirection) MarshalJSON() ([]byte, error) {
	switch c {
	case FlowActive:
		return json.Marshal("active")
	case FlowPassive:
		return json.Marshal("passive")
	case FlowUnknown:
		return json.Marshal("unknown")
	}
	return nil, errors.New("unreachable code")
}

// FilterPorts are ports to filter output.
type FilterPorts struct {
	Active  []string
	Passive []string
}

// flow represents statistics of a connection to other host and port.
type flow struct {
	originalSaddr   string
	originalDaddr   string
	originalSport   string
	originalDport   string
	originalPackets int64
	originalBytes   int64
	replySaddr      string
	replyDaddr      string
	replySport      string
	replyDport      string
	replyPackets    int64
	replyBytes      int64
}

// HostFlowStat represents statistics of a host flow.
type HostFlowStat struct {
	TotalInboundPackets  int64 `json:"total_inbound_packets"`
	TotalInboundBytes    int64 `json:"total_inbound_bytes"`
	TotalOutboundPackets int64 `json:"total_outbound_packets"`
	TotalOutboundBytes   int64 `json:"total_outbound_bytes"`
}

// String returns the string representation of the HostFlowStat.
func (s *HostFlowStat) String() string {
	return fmt.Sprintf("%d \t%d \t%d \t%d", s.TotalInboundPackets, s.TotalInboundBytes, s.TotalOutboundPackets, s.TotalOutboundBytes)
}

// AddrPort are <addr>:<port>
type AddrPort struct {
	Addr string `json:"addr"`
	Port string `json:"port"`
}

// String returns the string representation of the AddrPort.
func (a *AddrPort) String() string {
	return net.JoinHostPort(a.Addr, a.Port)
}

// HostFlow represents a `host flow`.
type HostFlow struct {
	Direction FlowDirection `json:"direction"`
	Local     *AddrPort     `json:"local"`
	Peer      *AddrPort     `json:"peer"`
	Stat      *HostFlowStat `json:"stat"`
}

// HasDirection returns whether .
func (f *HostFlow) HasDirection(dire FlowDirection) bool {
	return f.Direction&dire == 0
}

// String returns the string representation of HostFlow.
func (f *HostFlow) String() string {
	return fmt.Sprintf("%s\t --> \t%s \t%s", f.Local, f.Peer, f.Stat)
}

// ReplaceLookupedName replaces f.Addr into lookuped name.
func (f *HostFlow) ReplaceLookupedName() {
	f.Peer.Addr = netutil.ResolveAddr(f.Peer.Addr)
}

// UniqKey returns the unique key for connections aggregation
func (f *HostFlow) UniqKey() string {
	return fmt.Sprintf("%d-%s-%s", f.Direction, f.Local, f.Peer)
}

// HostFlows represents a group of host flow by unique key.
type HostFlows map[string]*HostFlow

func (hf HostFlows) insert(flow *HostFlow) {
	key := flow.UniqKey()
	if _, ok := hf[key]; !ok {
		hf[key] = flow
		return
	}
	switch flow.Direction {
	case FlowActive:
		hf[key].Stat.TotalInboundPackets += flow.Stat.TotalInboundPackets
		hf[key].Stat.TotalInboundBytes += flow.Stat.TotalInboundBytes
		hf[key].Stat.TotalOutboundPackets += flow.Stat.TotalOutboundPackets
		hf[key].Stat.TotalOutboundBytes += flow.Stat.TotalOutboundBytes
	case FlowPassive:
		hf[key].Stat.TotalInboundPackets += flow.Stat.TotalInboundPackets
		hf[key].Stat.TotalInboundBytes += flow.Stat.TotalInboundBytes
		hf[key].Stat.TotalOutboundPackets += flow.Stat.TotalOutboundPackets
		hf[key].Stat.TotalOutboundBytes += flow.Stat.TotalOutboundBytes
	}
	return
}

// MarshalJSON returns list formats not map.
func (hf HostFlows) MarshalJSON() ([]byte, error) {
	list := make([]HostFlow, 0, len(hf))
	for _, f := range hf {
		list = append(list, *f)
	}
	return json.Marshal(list)
}

// toHostFlow converts into HostFlow.
func (f *flow) toHostFlow(localAddrs []string, fports FilterPorts) *HostFlow {
	var (
		direction  FlowDirection
		addr, port string
	)
	for _, localAddr := range localAddrs {
		// not filter by ports on ActiveOpen connection if ports is empty
		if f.originalSaddr == localAddr && (len(fports.Active) == 0 || contains(fports.Active, f.originalDport)) {
			direction, addr, port = FlowActive, f.originalDaddr, f.originalDport
			break
		}
		if f.replyDaddr == localAddr && (len(fports.Active) == 0 || contains(fports.Active, f.replySport)) {
			direction, addr, port = FlowActive, f.replySaddr, f.replySport
			break
		}
		if f.originalDaddr == localAddr && contains(fports.Passive, f.originalDport) {
			direction, addr, port = FlowPassive, f.originalSaddr, f.originalDport // not OriginalSport
			break
		}
		if f.replySaddr == localAddr && contains(fports.Passive, f.replySport) {
			direction, addr, port = FlowPassive, f.replyDaddr, f.replySport // not ReplyDport
			break
		}
	}
	switch direction {
	case FlowUnknown:
		return nil
	case FlowActive:
		return &HostFlow{
			Direction: FlowActive,
			Local:     &AddrPort{Addr: "localhost", Port: "many"},
			Peer:      &AddrPort{Addr: addr, Port: port},
			Stat: &HostFlowStat{
				TotalInboundPackets:  f.replyPackets,
				TotalInboundBytes:    f.replyBytes,
				TotalOutboundPackets: f.originalPackets,
				TotalOutboundBytes:   f.originalBytes,
			},
		}
	case FlowPassive:
		return &HostFlow{
			Direction: FlowPassive,
			Local:     &AddrPort{Addr: "localhost", Port: port},
			Peer:      &AddrPort{Addr: addr, Port: "many"},
			Stat: &HostFlowStat{
				TotalInboundPackets:  f.originalPackets,
				TotalInboundBytes:    f.originalBytes,
				TotalOutboundPackets: f.replyPackets,
				TotalOutboundBytes:   f.replyBytes,
			},
		}
	}
	return nil
}

func parseLine(line string) *flow {
	flow := &flow{}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		log.Fatalf("unexpected line: %s\n", line)
	}
	if fields[0] != "tcp" {
		return nil
	}
	var packets, bytes bool
	if strings.Contains(line, "packets=") {
		packets = true
	}
	if strings.Contains(line, "bytes=") {
		bytes = true
	}
	if strings.Contains(line, "[UNREPLIED]") {
		// tcp      6 367755 ESTABLISHED src=10.0.0.1 dst=10.0.0.2 sport=3306 dport=38205 packets=1 bytes=52 [UNREPLIED] src=10.0.0.2 dst=10.0.0.1 sport=38205 dport=3306 packets=0 bytes=0 mark=0 secmark=0 use=1
		i := 4
		flow.originalSaddr = strings.Split(fields[i], "=")[1]
		flow.originalDaddr = strings.Split(fields[i+1], "=")[1]
		flow.originalSport = strings.Split(fields[i+2], "=")[1]
		flow.originalDport = strings.Split(fields[i+3], "=")[1]
		i = i + 4
		if bytes {
			flow.originalPackets, _ = strconv.ParseInt(strings.Split(fields[i], "=")[1], 10, 64)
			i++
		}
		if packets {
			flow.originalBytes, _ = strconv.ParseInt(strings.Split(fields[i], "=")[1], 10, 64)
			i++
		}
		i = i + 1
		flow.replySaddr = strings.Split(fields[i], "=")[1]
		flow.replyDaddr = strings.Split(fields[i+1], "=")[1]
		flow.replySport = strings.Split(fields[i+2], "=")[1]
		flow.replyDport = strings.Split(fields[i+3], "=")[1]
		i = i + 4
		if packets {
			flow.replyPackets, _ = strconv.ParseInt(strings.Split(fields[i], "=")[1], 10, 64)
			i++
		}
		if bytes {
			flow.replyBytes, _ = strconv.ParseInt(strings.Split(fields[i], "=")[1], 10, 64)
			i++
		}
		return flow
	} else if strings.Contains(line, "[ASSURED]") {
		// tcp      6 5 CLOSE src=10.0.0.10 dst=10.0.0.11 sport=41143 dport=443 packets=3 bytes=164 src=10.0.0.11 dst=10.0.0.10 sport=443 dport=41143 packets=1 bytes=60 [ASSURED] mark=0 secmark=0 use=1
		i := 4
		flow.originalSaddr = strings.Split(fields[i], "=")[1]
		flow.originalDaddr = strings.Split(fields[i+1], "=")[1]
		flow.originalSport = strings.Split(fields[i+2], "=")[1]
		flow.originalDport = strings.Split(fields[i+3], "=")[1]
		i = i + 4
		if packets {
			flow.originalPackets, _ = strconv.ParseInt(strings.Split(fields[i], "=")[1], 10, 64)
			i++
		}
		if bytes {
			flow.originalBytes, _ = strconv.ParseInt(strings.Split(fields[i], "=")[1], 10, 64)
			i++
		}
		flow.replySaddr = strings.Split(fields[i], "=")[1]
		flow.replyDaddr = strings.Split(fields[i+1], "=")[1]
		flow.replySport = strings.Split(fields[i+2], "=")[1]
		flow.replyDport = strings.Split(fields[i+3], "=")[1]
		i = i + 4
		if packets {
			flow.replyPackets, _ = strconv.ParseInt(strings.Split(fields[i], "=")[1], 10, 64)
			i++
		}
		if bytes {
			flow.replyBytes, _ = strconv.ParseInt(strings.Split(fields[i], "=")[1], 10, 64)
			i++
		}
		return flow
	}
	return nil
}

// ParseEntries parses '/proc/net/nf_conntrack or /proc/net/ip_conntrack'.
func ParseEntries(r io.Reader, fports FilterPorts) (HostFlows, error) {
	localAddrs, err := netutil.LocalIPAddrs()
	if err != nil {
		return nil, err
	}
	hostFlows := HostFlows{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		flow := parseLine(line)
		if flow == nil {
			continue
		}
		hostFlow := flow.toHostFlow(localAddrs, fports)
		if hostFlow == nil {
			continue
		}
		hostFlows.insert(hostFlow)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return hostFlows, nil
}
