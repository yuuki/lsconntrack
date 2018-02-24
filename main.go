package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
)

const (
	PROC_CONNTRACK = "/proc/net/ip_conntrack" // old kernel
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

func parseConntrack(addrs []string) (map[string]int64, error) {
	f, err := os.Open(PROC_CONNTRACK)
	if err != nil {
		return nil, err
	}
	daddrs := make(map[string]int64)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		for _, addr := range addrs {
			if !strings.Contains(line, "src="+addr) {
				continue
			}
		}
		for _, field := range strings.Fields(line) {
			if strings.HasPrefix(field, "dst=") {
				daddr := strings.SplitN(field, "=", 2)[1]
				daddrs[daddr] += 1
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return daddrs, nil
}

func main() {
	addrs, err := localIPaddrs()
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	daddrs, err := parseConntrack(addrs)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	for addr, cnt := range daddrs {
		fmt.Printf("%s %d\n", addr, cnt)
	}
}
