// Package cmdshark provides powerful shell command extraction from binary strings and malware samples.
package cmdshark

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Command represents an extracted shell command with metadata
type Command struct {
	Command            string   `json:"command"`
	Confidence         float64  `json:"confidence"`
	FragmentationLevel int      `json:"fragmentation_level"`
	Methods            []string `json:"methods"`
	SyntaxOK           bool     `json:"syntax_ok"`
	Tags               []string `json:"tags"`
}

// Extractor is the main interface for command extraction
type Extractor struct {
	extractor *CommandExtractor
}

// NewExtractor creates a new command extractor with default configuration
func NewExtractor() *Extractor {
	return &Extractor{
		extractor: NewCommandExtractor(),
	}
}

// NewExtractorWithConfig creates a new command extractor with custom configuration
func NewExtractorWithConfig(config Config) *Extractor {
	extractor := NewCommandExtractor()
	extractor.config = config
	return &Extractor{
		extractor: extractor,
	}
}

// ExtractFromString extracts commands from a single string
func (e *Extractor) ExtractFromString(text string) []Command {
	extracted := e.extractor.ExtractFromBlob(text)
	return e.convertToCommands(extracted)
}

// ExtractFromFragments extracts commands from multiple string fragments
func (e *Extractor) ExtractFromFragments(fragments []string) []Command {
	extracted := e.extractor.ExtractCommands(fragments)
	return e.convertToCommands(extracted)
}

// SetMinConfidence adjusts the minimum confidence threshold
func (e *Extractor) SetMinConfidence(confidence float64) {
	e.extractor.config.MinConfidence = confidence
}

// SetDeduplication enables or disables command deduplication
func (e *Extractor) SetDeduplication(enabled bool) {
	e.extractor.config.Dedupe = enabled
}

// SetMaxFragments sets the maximum number of fragments per command
func (e *Extractor) SetMaxFragments(maxFragments int) {
	e.extractor.config.MaxFragmentsTotal = maxFragments
}

// GetConfig returns the current configuration
func (e *Extractor) GetConfig() Config {
	return e.extractor.config
}

// FilterByConfidence filters commands by minimum confidence
func (e *Extractor) FilterByConfidence(commands []Command, minConfidence float64) []Command {
	var filtered []Command
	for _, cmd := range commands {
		if cmd.Confidence >= minConfidence {
			filtered = append(filtered, cmd)
		}
	}
	return filtered
}

// FilterByTags filters commands by tags
func (e *Extractor) FilterByTags(commands []Command, tags []string) []Command {
	var filtered []Command
	for _, cmd := range commands {
		for _, tag := range tags {
			if contains(cmd.Tags, tag) {
				filtered = append(filtered, cmd)
				break
			}
		}
	}
	return filtered
}

// GetNetworkCommands returns commands tagged as network-related
func (e *Extractor) GetNetworkCommands(commands []Command) []Command {
	return e.FilterByTags(commands, []string{"network"})
}

// GetExecutionCommands returns commands tagged as execution-related
func (e *Extractor) GetExecutionCommands(commands []Command) []Command {
	return e.FilterByTags(commands, []string{"execution"})
}

// GetSuspiciousCommands returns commands tagged as suspicious
func (e *Extractor) GetSuspiciousCommands(commands []Command) []Command {
	return e.FilterByTags(commands, []string{"suspicious"})
}

// GetFileOperationCommands returns commands tagged as file operations
func (e *Extractor) GetFileOperationCommands(commands []Command) []Command {
	return e.FilterByTags(commands, []string{"file-ops"})
}

// GetMacOSCommands returns commands tagged as macOS-specific
func (e *Extractor) GetMacOSCommands(commands []Command) []Command {
	return e.FilterByTags(commands, []string{"macos"})
}

// ToJSON converts commands to JSON format
func (e *Extractor) ToJSON(commands []Command) (string, error) {
	data, err := json.MarshalIndent(commands, "", "  ")
	return string(data), err
}

// convertToCommands converts internal ExtractedCommand to public Command
func (e *Extractor) convertToCommands(extracted []ExtractedCommand) []Command {
	commands := make([]Command, len(extracted))
	for i, cmd := range extracted {
		commands[i] = Command{
			Command:            cmd.Command,
			Confidence:         cmd.Confidence,
			FragmentationLevel: cmd.FragmentationLevel,
			Methods:            cmd.Methods,
			SyntaxOK:           cmd.SyntaxOK,
			Tags:               e.classifyCommand(cmd.Command),
		}
	}
	return commands
}

// classifyCommand automatically tags commands by type
func (e *Extractor) classifyCommand(command string) []string {
	var tags []string
	
	networkCommands := regexp.MustCompile(`^(curl|wget|nc|ncat|telnet|ssh|scp|sftp|ftp|ping|nslookup|dig)\b`)
	if networkCommands.MatchString(command) {
		tags = append(tags, "network")
	}
	
	executionCommands := regexp.MustCompile(`^(bash|sh|zsh|ksh|fish|dash|python|python3|perl|ruby|node|osascript|powershell|cmd)\b`)
	if executionCommands.MatchString(command) {
		tags = append(tags, "execution")
	}
	
	if strings.Contains(command, "rm -rf") || strings.Contains(command, "sudo") ||
	   strings.Contains(command, "kill") || strings.Contains(command, "killall") ||
	   strings.Contains(command, "/tmp/") || strings.Contains(command, "nohup") {
		tags = append(tags, "suspicious")
	}
	
	fileOpsCommands := regexp.MustCompile(`^(cp|mv|ln|mkdir|rmdir|chmod|chown|tar|zip|unzip|gzip|gunzip)\b`)
	if fileOpsCommands.MatchString(command) {
		tags = append(tags, "file-ops")
	}
	
	macosCommands := regexp.MustCompile(`^(osascript|launchctl|spctl|codesign|xattr|plutil|ditto|hdiutil|installer)\b`)
	if macosCommands.MatchString(command) || strings.Contains(command, ".plist") {
		tags = append(tags, "macos")
	}
	
	return tags
}

// Helper function to check if slice contains string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}