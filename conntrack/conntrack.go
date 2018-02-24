package conntrack

import (
	"bufio"
	"errors"
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
func ParseEntries() (map[string]int64, error) {
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
	daddrs := make(map[string]int64)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		for _, addr := range localAddrs {
			if !strings.Contains(line, "src="+addr) {
				continue
			}
		}
		for _, field := range strings.Fields(line) {
			if strings.HasPrefix(field, "dst=") {
				daddr := strings.SplitN(field, "=", 2)[1]
				daddrs[daddr]++
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return daddrs, nil
}
