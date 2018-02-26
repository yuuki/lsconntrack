package conntrack

import "testing"

func TestLocalIPAddrss(t *testing.T) {
	addrs, err := localIPaddrs()
	if err != nil {
		t.Fatalf("should not raise error: %v", err)
	}
	if len(addrs) == 0 {
		t.Error("localIPAddrs() should not be len == 0")
	}
}

func TestParseLine(t *testing.T) {
	t.Run("[UNREPLIRED]", func(t *testing.T) {
		line := "tcp      6 367755 ESTABLISHED src=10.0.0.1 dst=10.0.0.2 sport=3306 dport=38205 packets=1 bytes=52 [UNREPLIED] src=10.0.0.2 dst=10.0.0.1 sport=38205 dport=3306 packets=0 bytes=0 mark=0 secmark=0 use=1"
		rstat := parseLine(line)
		if rstat.OriginalSaddr != "10.0.0.1" {
			t.Errorf("OriginalSaddr should be 10.0.0.1, not %v", rstat.OriginalSaddr)
		}
		if rstat.OriginalDaddr != "10.0.0.2" {
			t.Errorf("OriginalDaddr should be 10.0.0.2, not %v", rstat.OriginalDaddr)
		}
		if rstat.OriginalSport != "3306" {
			t.Errorf("OriginalSport should be 3306, not %v", rstat.OriginalSport)
		}
		if rstat.OriginalDport != "38205" {
			t.Errorf("OriginalSport should be 38205, not %v", rstat.OriginalDport)
		}
		if rstat.OriginalPackets != 1 {
			t.Errorf("OriginalPackets should be 1, not %v", rstat.OriginalPackets)
		}
		if rstat.OriginalBytes != 52 {
			t.Errorf("OriginalBytes should be 52, not %v", rstat.OriginalBytes)
		}
		if rstat.ReplySaddr != "10.0.0.2" {
			t.Errorf("ReplySaddr should be 10.0.0.2, not %v", rstat.ReplySaddr)
		}
		if rstat.ReplyDaddr != "10.0.0.1" {
			t.Errorf("ReplySaddr should be 10.0.0.1, not %v", rstat.ReplyDaddr)
		}
		if rstat.ReplySport != "38205" {
			t.Errorf("ReplySaddr should be 38205, not %v", rstat.ReplySport)
		}
		if rstat.ReplyDport != "3306" {
			t.Errorf("ReplySaddr should be 3306, not %v", rstat.ReplyDport)
		}
		if rstat.ReplyPackets != 0 {
			t.Errorf("ReplyPackets should be 0, not %v", rstat.ReplyPackets)
		}
		if rstat.ReplyBytes != 0 {
			t.Errorf("ReplyBytes should be 0, not %v", rstat.ReplyBytes)
		}
	})

	t.Run("[ASSURED]", func(t *testing.T) {
		line := "tcp      6 5 CLOSE src=10.0.0.10 dst=10.0.0.11 sport=41143 dport=443 packets=3 bytes=164 src=10.0.0.11 dst=10.0.0.10 sport=443 dport=41143 packets=1 bytes=60 [ASSURED] mark=0 secmark=0 use=1"
		rstat := parseLine(line)
		if rstat.OriginalSaddr != "10.0.0.10" {
			t.Errorf("OriginalSaddr should be 10.0.0.10, not %v", rstat.OriginalSaddr)
		}
		if rstat.OriginalDaddr != "10.0.0.11" {
			t.Errorf("OriginalDaddr should be 10.0.0.11, not %v", rstat.OriginalDaddr)
		}
		if rstat.OriginalSport != "41143" {
			t.Errorf("OriginalSport should be 41143, not %v", rstat.OriginalSport)
		}
		if rstat.OriginalDport != "443" {
			t.Errorf("OriginalSport should be 443, not %v", rstat.OriginalDport)
		}
		if rstat.OriginalPackets != 3 {
			t.Errorf("OriginalPackets should be 3, not %v", rstat.OriginalPackets)
		}
		if rstat.OriginalBytes != 164 {
			t.Errorf("OriginalBytes should be 164, not %v", rstat.OriginalBytes)
		}
		if rstat.ReplySaddr != "10.0.0.11" {
			t.Errorf("ReplySaddr should be 10.0.0.11, not %v", rstat.ReplySaddr)
		}
		if rstat.ReplyDaddr != "10.0.0.10" {
			t.Errorf("ReplySaddr should be 10.0.0.10, not %v", rstat.ReplyDaddr)
		}
		if rstat.ReplySport != "443" {
			t.Errorf("ReplySaddr should be 443, not %v", rstat.ReplySport)
		}
		if rstat.ReplyDport != "41143" {
			t.Errorf("ReplySaddr should be 41143, not %v", rstat.ReplyDport)
		}
		if rstat.ReplyPackets != 1 {
			t.Errorf("ReplyPackets should be 1, not %v", rstat.ReplyPackets)
		}
		if rstat.ReplyBytes != 60 {
			t.Errorf("ReplyBytes should be 60, not %v", rstat.ReplyBytes)
		}
	})
}
