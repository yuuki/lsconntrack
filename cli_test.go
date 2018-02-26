package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun_global(t *testing.T) {
	tests := []struct {
		desc           string
		arg            string
		expectedStatus int
		expectedSubOut string
		expectedSubErr string
	}{
		{
			desc:           "no arg",
			arg:            "lsconntrack",
			expectedStatus: exitCodeArgumentsError,
			expectedSubErr: "Usage: lsconntrack",
		},
		{
			desc:           "undefined flag",
			arg:            "lsconntrack --undefined",
			expectedStatus: exitCodeFlagParseError,
			expectedSubErr: "flag provided but not defined",
		},
	}
	for _, tc := range tests {
		outStream, errStream := new(bytes.Buffer), new(bytes.Buffer)
		cli := &CLI{outStream: outStream, errStream: errStream}
		args := strings.Split(tc.arg, " ")

		status := cli.Run(args)
		if status != tc.expectedStatus {
			t.Errorf("desc: %q, status should be %v, not %v", tc.desc, tc.expectedStatus, status)
		}

		if !strings.Contains(outStream.String(), tc.expectedSubOut) {
			t.Errorf("desc: %q, subout should contain %q, got %q", tc.desc, tc.expectedSubOut, outStream.String())
		}
		if !strings.Contains(errStream.String(), tc.expectedSubErr) {
			t.Errorf("desc: %q, subout should contain %q, got %q", tc.desc, tc.expectedSubErr, errStream.String())
		}
	}
}
