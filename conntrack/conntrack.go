package conntrack

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"

	gnet "github.com/shirou/gopsutil/net"
)

type ConnMode int

const (
	ConnOther ConnMode = 1 << iota
	ConnActive
	ConnPassive
)

type FilterPorts struct {
	Active  []string
	Passive []string
}

// RawConnStat represents statistics of a connection to other host and port.
type RawConnStat struct {
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

type ConnStatByAddrPort map[string]*ConnStat

// ConnStat represents statistics of a connection to localhost or from localhost.
type ConnStat struct {
	Mode                 ConnMode
	Addr                 string `json:"addr"`
	Port                 string `json:"port"`
	TotalInboundPackets  int64  `json:"total_inbound_packets"`
	TotalInboundBytes    int64  `json:"total_inbound_bytes"`
	TotalOutboundPackets int64  `json:"total_outbound_packets"`
	TotalOutboundBytes   int64  `json:"total_outbound_bytes"`
}

// Dump dumps ConnStat.
func (stat *ConnStat) Dump() string {
	if stat.Mode == ConnActive {
		return fmt.Sprintf("localhost\t --> \t%s:%s \t%d\t%d\t%d\t%d", stat.Addr, stat.Port, stat.TotalInboundPackets, stat.TotalInboundBytes, stat.TotalOutboundPackets, stat.TotalOutboundBytes)
	} else if stat.Mode == ConnPassive {
		return fmt.Sprintf("localhost:%s\t <-- \t%s \t%d\t%d\t%d\t%d", stat.Port, stat.Addr, stat.TotalInboundPackets, stat.TotalInboundBytes, stat.TotalOutboundPackets, stat.TotalOutboundBytes)
	}
	return ""
}

func parseRawConnStat(rstat *RawConnStat, localAddrs []string, fports FilterPorts) *ConnStat {
	var (
		mode       ConnMode
		addr, port string
	)
	for _, localAddr := range localAddrs {
		// not filter by ports on ActiveOpen connection if ports is empty
		if rstat.OriginalSaddr == localAddr && (len(fports.Active) == 0 || contains(fports.Active, rstat.OriginalDport)) {
			mode, addr, port = ConnActive, rstat.OriginalDaddr, rstat.OriginalDport
			break
		}
		if rstat.ReplyDaddr == localAddr && (len(fports.Active) == 0 || contains(fports.Active, rstat.ReplySport)) {
			mode, addr, port = ConnActive, rstat.ReplySaddr, rstat.ReplySport
			break
		}
		if rstat.OriginalDaddr == localAddr && contains(fports.Passive, rstat.OriginalDport) {
			mode, addr, port = ConnPassive, rstat.OriginalSaddr, rstat.OriginalDport // not OriginalSport
			break
		}
		if rstat.ReplySaddr == localAddr && contains(fports.Passive, rstat.ReplySport) {
			mode, addr, port = ConnPassive, rstat.ReplyDaddr, rstat.ReplySport // not ReplyDport
			break
		}
	}
	switch mode {
	case ConnOther:
		return nil
	case ConnActive:
		return &ConnStat{
			Mode:                 ConnActive,
			Addr:                 addr,
			Port:                 port,
			TotalInboundPackets:  rstat.ReplyPackets,
			TotalInboundBytes:    rstat.ReplyBytes,
			TotalOutboundPackets: rstat.OriginalPackets,
			TotalOutboundBytes:   rstat.OriginalBytes,
		}
	case ConnPassive:
		return &ConnStat{
			Mode:                 ConnPassive,
			Addr:                 addr,
			Port:                 port,
			TotalInboundPackets:  rstat.OriginalPackets,
			TotalInboundBytes:    rstat.OriginalBytes,
			TotalOutboundPackets: rstat.ReplyPackets,
			TotalOutboundBytes:   rstat.ReplyBytes,
		}
	}
	return nil
}

func (c ConnStatByAddrPort) insert(stat *ConnStat) {
	key := fmt.Sprintf("%d-%s", stat.Mode, net.JoinHostPort(stat.Addr, stat.Port))
	if _, ok := c[key]; !ok {
		c[key] = stat
		return
	}
	switch stat.Mode {
	case ConnActive:
		c[key].TotalInboundPackets += stat.TotalInboundPackets
		c[key].TotalInboundBytes += stat.TotalInboundBytes
		c[key].TotalOutboundPackets += stat.TotalOutboundPackets
		c[key].TotalOutboundBytes += stat.TotalOutboundBytes
	case ConnPassive:
		c[key].TotalInboundPackets += stat.TotalInboundPackets
		c[key].TotalInboundBytes += stat.TotalInboundBytes
		c[key].TotalOutboundPackets += stat.TotalOutboundPackets
		c[key].TotalOutboundBytes += stat.TotalOutboundBytes
	}
	return
}

// ParseEntries parses '/proc/net/nf_conntrack or /proc/net/ip_conntrack'.
func ParseEntries(r io.Reader, fports FilterPorts) (ConnStatByAddrPort, error) {
	localAddrs, err := localIPaddrs()
	if err != nil {
		return nil, err
	}
	entries := ConnStatByAddrPort{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		rstat := parseLine(line)
		if rstat == nil {
			continue
		}
		stat := parseRawConnStat(rstat, localAddrs, fports)
		if stat == nil {
			continue
		}
		entries.insert(stat)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func localIPaddrs() ([]string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	addrStrings := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				addrStrings = append(addrStrings, ipnet.IP.String())
			}
		}
	}
	return addrStrings, nil
}

// LocalListeningPorts returns the local listening ports.
// eg. [199, 111, 46131, 53, 8953, 25, 2812, 80, 8081, 22]
// -----------------------------------------------------------------------------------
// [y_uuki@host ~]$ netstat -tln
// Active Internet connections (only servers)
// Proto Recv-Q Send-Q Local Address               Foreign Address             State
// tcp        0      0 0.0.0.0:199                 0.0.0.0:*                   LISTEN
// tcp        0      0 0.0.0.0:111                 0.0.0.0:*                   LISTEN
// tcp        0      0 0.0.0.0:46131               0.0.0.0:*                   LISTEN
// tcp        0      0 127.0.0.1:53                0.0.0.0:*                   LISTEN
// tcp        0      0 127.0.0.1:8953              0.0.0.0:*                   LISTEN
// tcp        0      0 127.0.0.1:25                0.0.0.0:*                   LISTEN
// tcp        0      0 0.0.0.0:2812                0.0.0.0:*                   LISTEN
// tcp        0      0 :::80                       :::*                        LISTEN
// tcp        0      0 :::8081                     :::*                        LISTEN
// tcp        0      0 :::22                       :::*                        LISTEN
func LocalListeningPorts() ([]string, error) {
	conns, err := gnet.Connections("tcp")
	if err != nil {
		return nil, err
	}
	ports := []string{}
	for _, conn := range conns {
		if conn.Laddr.IP == "0.0.0.0" || conn.Laddr.IP == "127.0.0.1" || conn.Laddr.IP == "::" {
			ports = append(ports, fmt.Sprintf("%d", conn.Laddr.Port))
		}
	}
	return ports, nil
}

func parseLine(line string) *RawConnStat {
	stat := &RawConnStat{}
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
		stat.OriginalSaddr = strings.Split(fields[i], "=")[1]
		stat.OriginalDaddr = strings.Split(fields[i+1], "=")[1]
		stat.OriginalSport = strings.Split(fields[i+2], "=")[1]
		stat.OriginalDport = strings.Split(fields[i+3], "=")[1]
		i = i + 4
		if bytes {
			stat.OriginalPackets, _ = strconv.ParseInt(strings.Split(fields[i], "=")[1], 10, 64)
			i++
		}
		if packets {
			stat.OriginalBytes, _ = strconv.ParseInt(strings.Split(fields[i], "=")[1], 10, 64)
			i++
		}
		i = i + 1
		stat.ReplySaddr = strings.Split(fields[i], "=")[1]
		stat.ReplyDaddr = strings.Split(fields[i+1], "=")[1]
		stat.ReplySport = strings.Split(fields[i+2], "=")[1]
		stat.ReplyDport = strings.Split(fields[i+3], "=")[1]
		i = i + 4
		if packets {
			stat.ReplyPackets, _ = strconv.ParseInt(strings.Split(fields[i], "=")[1], 10, 64)
			i++
		}
		if bytes {
			stat.ReplyBytes, _ = strconv.ParseInt(strings.Split(fields[i], "=")[1], 10, 64)
			i++
		}
		return stat
	} else if strings.Contains(line, "[ASSURED]") {
		// tcp      6 5 CLOSE src=10.0.0.10 dst=10.0.0.11 sport=41143 dport=443 packets=3 bytes=164 src=10.0.0.11 dst=10.0.0.10 sport=443 dport=41143 packets=1 bytes=60 [ASSURED] mark=0 secmark=0 use=1
		i := 4
		stat.OriginalSaddr = strings.Split(fields[i], "=")[1]
		stat.OriginalDaddr = strings.Split(fields[i+1], "=")[1]
		stat.OriginalSport = strings.Split(fields[i+2], "=")[1]
		stat.OriginalDport = strings.Split(fields[i+3], "=")[1]
		i = i + 4
		if packets {
			stat.OriginalPackets, _ = strconv.ParseInt(strings.Split(fields[i], "=")[1], 10, 64)
			i++
		}
		if bytes {
			stat.OriginalBytes, _ = strconv.ParseInt(strings.Split(fields[i], "=")[1], 10, 64)
			i++
		}
		stat.ReplySaddr = strings.Split(fields[i], "=")[1]
		stat.ReplyDaddr = strings.Split(fields[i+1], "=")[1]
		stat.ReplySport = strings.Split(fields[i+2], "=")[1]
		stat.ReplyDport = strings.Split(fields[i+3], "=")[1]
		i = i + 4
		if packets {
			stat.ReplyPackets, _ = strconv.ParseInt(strings.Split(fields[i], "=")[1], 10, 64)
			i++
		}
		if bytes {
			stat.ReplyBytes, _ = strconv.ParseInt(strings.Split(fields[i], "=")[1], 10, 64)
			i++
		}
		return stat
	}
	return nil
}
