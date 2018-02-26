package conntrack

import "testing"

func TestLocalIPAddrs(t *testing.T) {
	addrs, err := localIPaddrs()
	if err != nil {
		t.Fatalf("should not raise error: %v", err)
	}
	if len(addrs) == 0 {
		t.Error("localIPAddrs() should not be len == 0")
	}
}
