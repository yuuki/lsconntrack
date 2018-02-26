package conntrack

import "os"

var (
	// IPConntrackPath are ip_conntrack path.
	IPConntrackPath = "/proc/net/ip_conntrack" // old kernel
	// NFConntrackPath are nf_conntrack path.
	NFConntrackPath = "/proc/net/nf_conntrack" // new kernel
)

// FindProcPath returns the conntrack proc path if it exists.
func FindProcPath() string {
	for _, path := range []string{IPConntrackPath, NFConntrackPath} {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

func contains(strs []string, s string) bool {
	for _, str := range strs {
		if str == s {
			return true
		}
	}
	return false
}
