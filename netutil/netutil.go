package netutil

import (
	"net"
	"strings"
)

// ResolveAddr lookup first hostname from IP Address.
func ResolveAddr(addr string) string {
	hostnames, _ := net.LookupAddr(addr)
	if len(hostnames) > 0 {
		return strings.TrimSuffix(hostnames[0], ".")
	}
	return addr
}
