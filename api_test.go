package cmdshark

import (
	"testing"
)

func TestExtractor_PublicAPI(t *testing.T) {
	extractor := NewExtractor()
	
	commands := extractor.ExtractFromString("bash -c 'echo hello world'")
	if len(commands) == 0 {
		t.Error("Expected to extract at least one command")
	}
	
	fragments := []string{"curl", "http://example.com", "|", "bash"}
	commands = extractor.ExtractFromFragments(fragments)
	if len(commands) == 0 {
		t.Error("Expected to extract commands from fragments")
	}
	
	config := extractor.GetConfig()
	if config.MinConfidence <= 0 {
		t.Error("Expected valid min confidence")
	}
	
	commands = extractor.ExtractFromString("bash -c echo test && curl http://example.com")
	filtered := extractor.FilterByConfidence(commands, 0.8)
	if len(filtered) > len(commands) {
		t.Error("Filtered commands should not exceed original")
	}
	
	commands = extractor.ExtractFromString("curl http://example.com && osascript -e 'display dialog \"test\"'")
	networkCmds := extractor.GetNetworkCommands(commands)
	macosCmds := extractor.GetMacOSCommands(commands)
	
	t.Logf("Found %d network commands", len(networkCmds))
	t.Logf("Found %d macOS commands", len(macosCmds))
	
	if len(commands) > 0 {
		jsonOutput, err := extractor.ToJSON(commands)
		if err != nil {
			t.Errorf("Failed to generate JSON: %v", err)
		}
		if len(jsonOutput) == 0 {
			t.Error("JSON output should not be empty")
		}
	}
}

func TestExtractor_CustomConfig(t *testing.T) {
	config := Config{
		MinConfidence:         0.3,
		MaxWindow:            15,
		MaxJoinChars:         800,
		Dedupe:               true,
		MaxFragmentsTotal:    30,
		MaxFragmentsPerSegment: 5,
	}
	
	extractor := NewExtractorWithConfig(config)
	
	commands := extractor.ExtractFromString("bash -c echo hello")
	if len(commands) == 0 {
		t.Error("Expected to extract commands with custom config")
	}
	
	actualConfig := extractor.GetConfig()
	if actualConfig.MinConfidence != config.MinConfidence {
		t.Errorf("Expected MinConfidence %f, got %f", config.MinConfidence, actualConfig.MinConfidence)
	}
}

func TestExtractor_NaturalLanguageFiltering(t *testing.T) {
	extractor := NewExtractor()
	
	naturalLanguageCases := []string{
		"time to copy the file",
		"time unavailable", 
		"node in intrusive list",
	}
	
	for _, testCase := range naturalLanguageCases {
		commands := extractor.ExtractFromString(testCase)
		if len(commands) > 0 {
			t.Logf("Note: Natural language %q extracted %d commands (may be expected)", 
				testCase, len(commands))
		}
	}
	
	validCommands := []string{
		"killall Terminal",
		"ditto -c -k file.zip",
		"/bin/sh",
	}
	
	for _, testCase := range validCommands {
		commands := extractor.ExtractFromString(testCase)
		if len(commands) == 0 {
			t.Errorf("Valid command %q was incorrectly filtered out", testCase)
		}
	}
}