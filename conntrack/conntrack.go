package conntrack

import (
	"bufio"
	"errors"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

var (
	// ConntrackPaths are conntrack entries paths.
	ConntrackPaths = []string{
		"/proc/net/ip_conntrack", // old kernel
		"/proc/net/nf_conntrack", // new kernel
	}
)

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
	Addr                 string
	Port                 string
	TotalInboundPackets  int64
	TotalInboundBytes    int64
	TotalOutboundPackets int64
	TotalOutboundBytes   int64
}

func (c ConnStatByAddrPort) insert(rstat *RawConnStat, localAddrs []string) {
	var stat *ConnStat
	for _, addr := range localAddrs {
		// direction: from localhost to destination
		if rstat.OriginalSaddr == addr {
			stat = &ConnStat{
				Addr:                 rstat.OriginalDaddr,
				Port:                 rstat.OriginalDport,
				TotalInboundPackets:  rstat.ReplyPackets,
				TotalInboundBytes:    rstat.ReplyBytes,
				TotalOutboundPackets: rstat.OriginalPackets,
				TotalOutboundBytes:   rstat.OriginalBytes,
			}
		} else if rstat.ReplyDaddr == addr {
			stat = &ConnStat{
				Addr:                 rstat.ReplySaddr,
				Port:                 rstat.ReplySport,
				TotalInboundPackets:  rstat.ReplyPackets,
				TotalInboundBytes:    rstat.ReplyBytes,
				TotalOutboundPackets: rstat.OriginalPackets,
				TotalOutboundBytes:   rstat.OriginalBytes,
			}
		}
	}
	if stat == nil {
		return
	}
	key := stat.Addr + ":" + stat.Port
	if _, ok := c[key]; !ok {
		c[key] = stat
		return
	}
	c[key].TotalInboundPackets += rstat.ReplyPackets
	c[key].TotalInboundBytes += rstat.ReplyBytes
	c[key].TotalOutboundPackets += rstat.OriginalPackets
	c[key].TotalOutboundBytes += rstat.OriginalBytes
	return
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

func findEntryPath() string {
	for _, path := range ConntrackPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

// ParseEntries parses '/proc/net/nf_conntrack or /proc/net/ip_conntrack'.
func ParseEntries() (ConnStatByAddrPort, error) {
	localAddrs, err := localIPaddrs()
	if err != nil {
		return nil, err
	}
	path := findEntryPath()
	if path == "" {
		return nil, errors.New("not found conntrack entries path: Please load conntrack module")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	dstat := ConnStatByAddrPort{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		stat := parseLine(line)
		if stat == nil {
			continue
		}
		dstat.insert(stat, localAddrs)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return dstat, nil
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
	if strings.Contains(line, "[UNREPLIED]") {
		// tcp      6 367755 ESTABLISHED src=10.0.0.1 dst=10.0.0.2 sport=3306 dport=38205 packets=1 bytes=52 [UNREPLIED] src=10.0.0.2 dst=10.0.0.1 sport=38205 dport=3306 packets=0 bytes=0 mark=0 secmark=0 use=1
		stat.OriginalSaddr = strings.Split(fields[4], "=")[1]
		stat.OriginalDaddr = strings.Split(fields[5], "=")[1]
		stat.OriginalSport = strings.Split(fields[6], "=")[1]
		stat.OriginalDport = strings.Split(fields[7], "=")[1]
		stat.OriginalPackets, _ = strconv.ParseInt(strings.Split(fields[8], "=")[1], 10, 64)
		stat.OriginalBytes, _ = strconv.ParseInt(strings.Split(fields[9], "=")[1], 10, 64)
		stat.ReplySaddr = strings.Split(fields[11], "=")[1]
		stat.ReplyDaddr = strings.Split(fields[12], "=")[1]
		stat.ReplySport = strings.Split(fields[13], "=")[1]
		stat.ReplyDport = strings.Split(fields[14], "=")[1]
		stat.ReplyPackets, _ = strconv.ParseInt(strings.Split(fields[15], "=")[1], 10, 64)
		stat.ReplyBytes, _ = strconv.ParseInt(strings.Split(fields[16], "=")[1], 10, 64)
		return stat
	} else if strings.Contains(line, "ASSURED") {
		// tcp      6 5 CLOSE src=10.0.0.10 dst=10.0.0.11 sport=41143 dport=443 packets=3 bytes=164 src=10.0.0.11 dst=10.0.0.10 sport=443 dport=41143 packets=1 bytes=60 [ASSURED] mark=0 secmark=0 use=1
		stat.OriginalSaddr = strings.Split(fields[4], "=")[1]
		stat.OriginalDaddr = strings.Split(fields[5], "=")[1]
		stat.OriginalSport = strings.Split(fields[6], "=")[1]
		stat.OriginalDport = strings.Split(fields[7], "=")[1]
		stat.OriginalPackets, _ = strconv.ParseInt(strings.Split(fields[8], "=")[1], 10, 64)
		stat.OriginalBytes, _ = strconv.ParseInt(strings.Split(fields[9], "=")[1], 10, 64)
		stat.ReplySaddr = strings.Split(fields[10], "=")[1]
		stat.ReplyDaddr = strings.Split(fields[11], "=")[1]
		stat.ReplySport = strings.Split(fields[12], "=")[1]
		stat.ReplyDport = strings.Split(fields[13], "=")[1]
		stat.ReplyPackets, _ = strconv.ParseInt(strings.Split(fields[14], "=")[1], 10, 64)
		stat.ReplyBytes, _ = strconv.ParseInt(strings.Split(fields[15], "=")[1], 10, 64)
		return stat
	}
	return nil
}
