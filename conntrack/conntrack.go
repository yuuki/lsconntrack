package conntrack

import (
	"bufio"
	"errors"
	"log"
	"net"
	"os"
	"strings"
)

var (
	// ConntrackPaths are conntrack entries paths.
	ConntrackPaths = []string{
		"/proc/net/ip_conntrack", // old kernel
		"/proc/net/nf_conntrack", // new kernel
	}
)

// ConnStat represents statistics of a connection to other host and port.
type ConnStat struct {
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

func (c ConnStatByAddrPort) insert(stat *ConnStat, localAddrs []string) {
	var destKey string
	for _, addr := range localAddrs {
		// direction: from localhost to destination
		if stat.OriginalSaddr == addr {
			destKey = stat.OriginalDaddr + ":" + stat.OriginalDport
		} else if stat.ReplyDaddr == addr {
			destKey = stat.ReplySaddr + ":" + stat.ReplySport
		}
	}
	if destKey == "" {
		return
	}
	if _, ok := c[destKey]; !ok {
		c[destKey] = stat
		return
	}
	// c[destKey].OriginalPackets += stat.OriginalPackets
	// c[destKey].OriginalBytes += stat.OriginalBytes
	// c[destKey].ReplyPackets += stat.ReplyPackets
	// c[destKey].ReplyBytes += stat.ReplyBytes
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

func parseLine(line string) *ConnStat {
	stat := &ConnStat{}
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
		stat.ReplySaddr = strings.Split(fields[11], "=")[1]
		stat.ReplyDaddr = strings.Split(fields[12], "=")[1]
		stat.ReplySport = strings.Split(fields[13], "=")[1]
		stat.ReplyDport = strings.Split(fields[14], "=")[1]
		return stat
	} else if strings.Contains(line, "ASSURED") {
		// tcp      6 5 CLOSE src=10.0.0.10 dst=10.0.0.11 sport=41143 dport=443 packets=3 bytes=164 src=10.0.0.11 dst=10.0.0.10 sport=443 dport=41143 packets=1 bytes=60 [ASSURED] mark=0 secmark=0 use=1
		stat.OriginalSaddr = strings.Split(fields[4], "=")[1]
		stat.OriginalDaddr = strings.Split(fields[5], "=")[1]
		stat.OriginalSport = strings.Split(fields[6], "=")[1]
		stat.OriginalDport = strings.Split(fields[7], "=")[1]
		stat.ReplySaddr = strings.Split(fields[10], "=")[1]
		stat.ReplyDaddr = strings.Split(fields[11], "=")[1]
		stat.ReplySport = strings.Split(fields[12], "=")[1]
		stat.ReplyDport = strings.Split(fields[13], "=")[1]
		return stat
	}
	return nil
}
