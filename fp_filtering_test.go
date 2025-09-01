package cmdshark

import (
	"testing"
)

func TestFalsePositiveFiltering(t *testing.T) {
	extractor := NewExtractor()
	
	testCases := []struct {
		name  string
		input string
	}{
		{"Service Protocol Def 1", "time 37/tcp timserver"},
		{"Service Protocol Def 2", "time 37/udp timserver"},
		{"Service Protocol Def 3", "telnet 23/tcp"},
		{"Service Protocol Def 4", "sftp 115/tcp"},
		{"Bare Command 1", "rmdir"},
		{"Bare Command 2", "chmod"},
		{"Bare Command 3", "mkdir"},
		{"Bare Command 4", "timeout"},
		{"Bare Command 5", "node"},
		{"Binary Garbage", "TuesdayJanuaryOctober/bin/shnil keyfloat32float64forcegcallocmWcpuprofallocmRunknowngctraceIO waitrunningsyscallwaitingforevernetworkUNKNOWN:events, goid= s=nil"},
		{"Incomplete Fragment 1", "killall chrome.WithoutCancel.WithDeadline("},
		{"Incomplete Fragment 2", "method.Call."},
		{"Natural Language 1", "timeout waiting for command"},
		{"Natural Language 2", "node value."},
		{"Natural Language 3", "time for backup"},
		{"Two Word Natural", "node value."},
		{"Waiting Command", "timeout waiting"},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			commands := extractor.ExtractFromString(tc.input)
			if len(commands) > 0 {
				t.Errorf("Expected no commands for %q, but got %d commands: %v", 
					tc.input, len(commands), commands)
				for _, cmd := range commands {
					t.Logf("  - Command: %q (confidence: %.3f)", cmd.Command, cmd.Confidence)
				}
			} else {
				t.Logf("✓ Correctly filtered out false positive: %q", tc.input)
			}
		})
	}
}

func TestValidCommandsNotFiltered(t *testing.T) {
	extractor := NewExtractor()
	
	testCases := []struct {
		name     string
		input    string
		expected int // minimum number of commands expected
	}{
		{"Kill with args", "killall Terminal", 1},
		{"Complex curl", `curl "https://example.com/script" | bash`, 1},
		{"Chmod with args", "chmod +x /tmp/script", 1},
		{"Multi-command", "ls -la && pwd", 2},
		{"Command with path", "/bin/bash -c 'echo hello'", 1},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			commands := extractor.ExtractFromString(tc.input)
			if len(commands) < tc.expected {
				t.Errorf("Expected at least %d commands for %q, but got %d", 
					tc.expected, tc.input, len(commands))
			} else {
				t.Logf("✓ Correctly preserved valid command: %q -> %d commands", 
					tc.input, len(commands))
			}
		})
	}
}

func TestSingleWordCommandFiltering(t *testing.T) {
	scorer := NewScorer()
	
	singleCommands := []string{
		"chmod", "mkdir", "rmdir", "timeout", "node", "time", "find",
		"grep", "sed", "awk", "sort", "uniq", "head", "tail", "cat",
	}
	
	for _, cmd := range singleCommands {
		if !scorer.isCommonFalsePositive(cmd) {
			t.Errorf("Expected %q to be filtered as false positive", cmd)
		} else {
			t.Logf("✓ Correctly identified %q as false positive", cmd)
		}
	}
}

func TestServiceProtocolDetection(t *testing.T) {
	scorer := NewScorer()
	
	servicePatterns := []string{
		"time 37/tcp timserver",
		"time 37/udp timserver",
		"telnet 23/tcp",
		"sftp 115/tcp",
		"ssh 22/tcp",
		"http 80/tcp",
		"https 443/tcp",
	}
	
	for _, pattern := range servicePatterns {
		if !scorer.isServiceProtocolDef(pattern) {
			t.Errorf("Expected %q to be detected as service protocol definition", pattern)
		} else {
			t.Logf("✓ Correctly identified service protocol: %q", pattern)
		}
	}
	
	validCommands := []string{
		"curl http://example.com",
		"ssh user@host",
		"telnet localhost 8080",
		"time ls -la",
	}
	
	for _, cmd := range validCommands {
		if scorer.isServiceProtocolDef(cmd) {
			t.Errorf("Expected %q to NOT be detected as service protocol definition", cmd)
		} else {
			t.Logf("✓ Correctly preserved valid command: %q", cmd)
		}
	}
}