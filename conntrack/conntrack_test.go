package conntrack

import "testing"

func TestParseLine(t *testing.T) {
	t.Run("[UNREPLIRED]", func(t *testing.T) {
		line := "tcp      6 367755 ESTABLISHED src=10.0.0.1 dst=10.0.0.2 sport=3306 dport=38205 packets=1 bytes=52 [UNREPLIED] src=10.0.0.2 dst=10.0.0.1 sport=38205 dport=3306 packets=0 bytes=0 mark=0 secmark=0 use=1"
		rstat := parseLine(line)
		if rstat.originalSaddr != "10.0.0.1" {
			t.Errorf("OriginalSaddr should be 10.0.0.1, not %v", rstat.originalSaddr)
		}
		if rstat.originalDaddr != "10.0.0.2" {
			t.Errorf("OriginalDaddr should be 10.0.0.2, not %v", rstat.originalDaddr)
		}
		if rstat.originalSport != "3306" {
			t.Errorf("OriginalSport should be 3306, not %v", rstat.originalSport)
		}
		if rstat.originalDport != "38205" {
			t.Errorf("OriginalSport should be 38205, not %v", rstat.originalDport)
		}
		if rstat.originalPackets != 1 {
			t.Errorf("OriginalPackets should be 1, not %v", rstat.originalPackets)
		}
		if rstat.originalBytes != 52 {
			t.Errorf("OriginalBytes should be 52, not %v", rstat.originalBytes)
		}
		if rstat.replySaddr != "10.0.0.2" {
			t.Errorf("ReplySaddr should be 10.0.0.2, not %v", rstat.replySaddr)
		}
		if rstat.replyDaddr != "10.0.0.1" {
			t.Errorf("ReplySaddr should be 10.0.0.1, not %v", rstat.replyDaddr)
		}
		if rstat.replySport != "38205" {
			t.Errorf("ReplySaddr should be 38205, not %v", rstat.replySport)
		}
		if rstat.replyDport != "3306" {
			t.Errorf("ReplySaddr should be 3306, not %v", rstat.replyDport)
		}
		if rstat.replyPackets != 0 {
			t.Errorf("ReplyPackets should be 0, not %v", rstat.replyPackets)
		}
		if rstat.replyBytes != 0 {
			t.Errorf("ReplyBytes should be 0, not %v", rstat.replyBytes)
		}
	})

	t.Run("[ASSURED]", func(t *testing.T) {
		line := "tcp      6 5 CLOSE src=10.0.0.10 dst=10.0.0.11 sport=41143 dport=443 packets=3 bytes=164 src=10.0.0.11 dst=10.0.0.10 sport=443 dport=41143 packets=1 bytes=60 [ASSURED] mark=0 secmark=0 use=1"
		rstat := parseLine(line)
		if rstat.originalSaddr != "10.0.0.10" {
			t.Errorf("OriginalSaddr should be 10.0.0.10, not %v", rstat.originalSaddr)
		}
		if rstat.originalDaddr != "10.0.0.11" {
			t.Errorf("OriginalDaddr should be 10.0.0.11, not %v", rstat.originalDaddr)
		}
		if rstat.originalSport != "41143" {
			t.Errorf("OriginalSport should be 41143, not %v", rstat.originalSport)
		}
		if rstat.originalDport != "443" {
			t.Errorf("OriginalSport should be 443, not %v", rstat.originalDport)
		}
		if rstat.originalPackets != 3 {
			t.Errorf("OriginalPackets should be 3, not %v", rstat.originalPackets)
		}
		if rstat.originalBytes != 164 {
			t.Errorf("OriginalBytes should be 164, not %v", rstat.originalBytes)
		}
		if rstat.replySaddr != "10.0.0.11" {
			t.Errorf("ReplySaddr should be 10.0.0.11, not %v", rstat.replySaddr)
		}
		if rstat.replyDaddr != "10.0.0.10" {
			t.Errorf("ReplySaddr should be 10.0.0.10, not %v", rstat.replyDaddr)
		}
		if rstat.replySport != "443" {
			t.Errorf("ReplySaddr should be 443, not %v", rstat.replySport)
		}
		if rstat.replyDport != "41143" {
			t.Errorf("ReplySaddr should be 41143, not %v", rstat.replyDport)
		}
		if rstat.replyPackets != 1 {
			t.Errorf("ReplyPackets should be 1, not %v", rstat.replyPackets)
		}
		if rstat.replyBytes != 60 {
			t.Errorf("ReplyBytes should be 60, not %v", rstat.replyBytes)
		}
	})
}
