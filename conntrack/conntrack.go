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

type FilterPorts struct {
	Active  []string
	Passive []string
}

// Flow represents statistics of a connection to other host and port.
type Flow struct {
	OriginalSaddr   string
	OriginalDaddr   string
	OriginalSport   string
	OriginalDport   string
	OriginalPackets int64
	OriginalBytes   int64
	ReplySaddr      string
	ReplyDaddr      string
	ReplySport      string
	ReplyDport      string
	ReplyPackets    int64
	ReplyBytes      int64
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

// HostFlow represents a `host flow`.
type HostFlow struct {
	Mode FlowDirection
	Addr string
	Port string
	Stat *HostFlowStat
}

// String returns the string representation of HostFlow.
func (f *HostFlow) String() string {
	if f.Mode == FlowActive {
		return fmt.Sprintf("localhost:many\t --> \t%s:%s \t%s", f.Addr, f.Port, f.Stat)
	} else if f.Mode == FlowPassive {
		return fmt.Sprintf("localhost:%s\t <-- \t%s:many \t%s", f.Port, f.Addr, f.Stat)
	}
	return ""
}

// ReplaceLookupedName replaces f.Addr into lookuped name.
func (f *HostFlow) ReplaceLookupedName() {
	f.Addr = netutil.ResolveAddr(f.Addr)
}

// MarshalJSON returns local addr port and peer addr post.
func (f *HostFlow) MarshalJSON() ([]byte, error) {
	type jsonHostFlow struct {
		Mode          FlowDirection `json:"mode"`
		LocalAddrPort string        `json:"local_addr_port"`
		PeerAddrPort  string        `json:"peer_addr_port"`
		Stat          *HostFlowStat `json:"stat"`
	}
	switch f.Mode {
	case FlowActive:
		return json.Marshal(jsonHostFlow{
			Mode:          f.Mode,
			LocalAddrPort: "localhost:many",
			PeerAddrPort:  net.JoinHostPort(f.Addr, f.Port),
			Stat:          f.Stat,
		})
	case FlowPassive:
		return json.Marshal(jsonHostFlow{
			Mode:          f.Mode,
			LocalAddrPort: net.JoinHostPort("localhost", f.Port),
			PeerAddrPort:  f.Addr + ":many",
			Stat:          f.Stat,
		})
	case FlowUnknown:
		return json.Marshal(jsonHostFlow{})
	}
	return nil, errors.New("unreachable code")
}

// HostFlows represents a group of host flow by unique key.
type HostFlows map[string]*HostFlow

func (hf HostFlows) insert(flow *HostFlow) {
	key := fmt.Sprintf("%d-%s", flow.Mode, net.JoinHostPort(flow.Addr, flow.Port))
	if _, ok := hf[key]; !ok {
		hf[key] = flow
		return
	}
	switch flow.Mode {
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
func (f *Flow) toHostFlow(localAddrs []string, fports FilterPorts) *HostFlow {
	var (
		mode       FlowDirection
		addr, port string
	)
	for _, localAddr := range localAddrs {
		// not filter by ports on ActiveOpen connection if ports is empty
		if f.OriginalSaddr == localAddr && (len(fports.Active) == 0 || contains(fports.Active, f.OriginalDport)) {
			mode, addr, port = FlowActive, f.OriginalDaddr, f.OriginalDport
			break
		}
		if f.ReplyDaddr == localAddr && (len(fports.Active) == 0 || contains(fports.Active, f.ReplySport)) {
			mode, addr, port = FlowActive, f.ReplySaddr, f.ReplySport
			break
		}
		if f.OriginalDaddr == localAddr && contains(fports.Passive, f.OriginalDport) {
			mode, addr, port = FlowPassive, f.OriginalSaddr, f.OriginalDport // not OriginalSport
			break
		}
		if f.ReplySaddr == localAddr && contains(fports.Passive, f.ReplySport) {
			mode, addr, port = FlowPassive, f.ReplyDaddr, f.ReplySport // not ReplyDport
			break
		}
	}
	switch mode {
	case FlowUnknown:
		return nil
	case FlowActive:
		return &HostFlow{
			Mode: FlowActive,
			Addr: addr,
			Port: port,
			Stat: &HostFlowStat{
				TotalInboundPackets:  f.ReplyPackets,
				TotalInboundBytes:    f.ReplyBytes,
				TotalOutboundPackets: f.OriginalPackets,
				TotalOutboundBytes:   f.OriginalBytes,
			},
		}
	case FlowPassive:
		return &HostFlow{
			Mode: FlowPassive,
			Addr: addr,
			Port: port,
			Stat: &HostFlowStat{
				TotalInboundPackets:  f.OriginalPackets,
				TotalInboundBytes:    f.OriginalBytes,
				TotalOutboundPackets: f.ReplyPackets,
				TotalOutboundBytes:   f.ReplyBytes,
			},
		}
	}
	return nil
}

func parseLine(line string) *Flow {
	flow := &Flow{}
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
		flow.OriginalSaddr = strings.Split(fields[i], "=")[1]
		flow.OriginalDaddr = strings.Split(fields[i+1], "=")[1]
		flow.OriginalSport = strings.Split(fields[i+2], "=")[1]
		flow.OriginalDport = strings.Split(fields[i+3], "=")[1]
		i = i + 4
		if bytes {
			flow.OriginalPackets, _ = strconv.ParseInt(strings.Split(fields[i], "=")[1], 10, 64)
			i++
		}
		if packets {
			flow.OriginalBytes, _ = strconv.ParseInt(strings.Split(fields[i], "=")[1], 10, 64)
			i++
		}
		i = i + 1
		flow.ReplySaddr = strings.Split(fields[i], "=")[1]
		flow.ReplyDaddr = strings.Split(fields[i+1], "=")[1]
		flow.ReplySport = strings.Split(fields[i+2], "=")[1]
		flow.ReplyDport = strings.Split(fields[i+3], "=")[1]
		i = i + 4
		if packets {
			flow.ReplyPackets, _ = strconv.ParseInt(strings.Split(fields[i], "=")[1], 10, 64)
			i++
		}
		if bytes {
			flow.ReplyBytes, _ = strconv.ParseInt(strings.Split(fields[i], "=")[1], 10, 64)
			i++
		}
		return flow
	} else if strings.Contains(line, "[ASSURED]") {
		// tcp      6 5 CLOSE src=10.0.0.10 dst=10.0.0.11 sport=41143 dport=443 packets=3 bytes=164 src=10.0.0.11 dst=10.0.0.10 sport=443 dport=41143 packets=1 bytes=60 [ASSURED] mark=0 secmark=0 use=1
		i := 4
		flow.OriginalSaddr = strings.Split(fields[i], "=")[1]
		flow.OriginalDaddr = strings.Split(fields[i+1], "=")[1]
		flow.OriginalSport = strings.Split(fields[i+2], "=")[1]
		flow.OriginalDport = strings.Split(fields[i+3], "=")[1]
		i = i + 4
		if packets {
			flow.OriginalPackets, _ = strconv.ParseInt(strings.Split(fields[i], "=")[1], 10, 64)
			i++
		}
		if bytes {
			flow.OriginalBytes, _ = strconv.ParseInt(strings.Split(fields[i], "=")[1], 10, 64)
			i++
		}
		flow.ReplySaddr = strings.Split(fields[i], "=")[1]
		flow.ReplyDaddr = strings.Split(fields[i+1], "=")[1]
		flow.ReplySport = strings.Split(fields[i+2], "=")[1]
		flow.ReplyDport = strings.Split(fields[i+3], "=")[1]
		i = i + 4
		if packets {
			flow.ReplyPackets, _ = strconv.ParseInt(strings.Split(fields[i], "=")[1], 10, 64)
			i++
		}
		if bytes {
			flow.ReplyBytes, _ = strconv.ParseInt(strings.Split(fields[i], "=")[1], 10, 64)
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
