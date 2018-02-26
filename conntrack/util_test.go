package conntrack

import "testing"

func TestContains(t *testing.T) {
	tests := []struct {
		in  []string
		s   string
		out bool
	}{
		{[]string{"3306", "11211", "80", "443", "6379"}, "11211", true},
		{[]string{"3306", "11211", "80", "443", "6379"}, "9000", false},
		{[]string{}, "3306", false},
	}

	for _, tt := range tests {
		if contains(tt.in, tt.s) != tt.out {
			t.Errorf("contains(%v, %v) == %v", tt.in, tt.s, tt.out)
		}
	}
}
