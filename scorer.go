package cmdshark

import (
	"math"
	"regexp"
	"strings"
)

type Scorer struct {
	lexer             Lexer
	helpPattern       *regexp.Regexp
	copyrightPattern  *regexp.Regexp
	frameworkPattern  *regexp.Regexp
	urlPattern        *regexp.Regexp
	assignPattern     *regexp.Regexp
	envRefPattern     *regexp.Regexp
	redirectPattern   *regexp.Regexp
}

type CommandFeatures struct {
	HasPipe       bool
	HasAnd        bool
	HasRedirect   bool
	HasURL        bool
	HasAssignment bool
	HasEnvRef     bool
	Length        int
}

func NewScorer() Scorer {
	return Scorer{
		lexer:            NewLexer(),
		helpPattern:      regexp.MustCompile(`^(?:Usage:|usage:)`),
		copyrightPattern: regexp.MustCompile(`Copyright`),
		frameworkPattern: regexp.MustCompile(`^(?:NS[A-Z]\w+|objc\w+|NSError\w*|CF\w+|kCF\w+)$`),
		urlPattern:       regexp.MustCompile(`https?://`),
		assignPattern:    regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=.*`),
		envRefPattern:    regexp.MustCompile(`\$[{(]?[A-Za-z_][A-Za-z0-9_]*[)}]?`),
		redirectPattern:  regexp.MustCompile(`[><]`),
	}
}

func (s *Scorer) ScoreCandidate(tokens []string, methods []string) (float64, bool) {
	if len(tokens) == 0 {
		return 0.0, false
	}
	
	joined := strings.Join(tokens, " ")
	head := tokens[0]
	
	if !s.lexer.IsHead(head) {
		return 0.0, false
	}
	
	if s.isCommonFalsePositive(joined) {
		return 0.0, false
	}
	
	features := s.extractFeatures(joined)
	confidence := s.calculateConfidence(features, joined)
	syntaxOK := s.checkSyntax(joined)
	
	return confidence, syntaxOK
}

func (s *Scorer) ScoreInlineCommand(cmd string) float64 {
	features := s.extractFeatures(cmd)
	return s.calculateInlineConfidence(features, cmd)
}

func (s *Scorer) extractFeatures(command string) CommandFeatures {
	return CommandFeatures{
		HasPipe:       strings.Contains(command, "|"),
		HasAnd:        strings.Contains(command, "&&"),
		HasRedirect:   s.redirectPattern.MatchString(command),
		HasURL:        s.urlPattern.MatchString(command),
		HasAssignment: s.assignPattern.MatchString(command),
		HasEnvRef:     s.envRefPattern.MatchString(command),
		Length:        len(command),
	}
}

func (s *Scorer) calculateConfidence(features CommandFeatures, command string) float64 {
	tokens := strings.Fields(command)
	base := 0.25
	
	if len(tokens) == 1 {
		base = 0.1 // Much lower base for single commands
	}
	
	if len(tokens) <= 3 && !features.HasPipe && !features.HasURL && !features.HasRedirect {
		base = 0.15 // Lower base for short commands without operators
	}
	
	if features.HasPipe {
		base += 0.15
	}
	if features.HasAnd {
		base += 0.12
	}
	if features.HasRedirect {
		base += 0.12
	}
	if features.HasURL {
		base += 0.18
	}
	if features.HasAssignment {
		base += 0.08
	}
	if features.HasEnvRef {
		base += 0.06
	}
	
	if features.Length < 8 {
		base -= 0.15 // Increased penalty for very short commands
	}
	if features.Length < 5 {
		base -= 0.2 // Even higher penalty for single chars/words
	}
	if features.Length > 400 {
		base -= 0.3 // Increased penalty for very long commands
	}
	if features.Length > 1000 {
		base -= 0.5 // Even higher penalty
	}
	
	if s.helpPattern.MatchString(command) || s.copyrightPattern.MatchString(command) {
		base -= 0.3
	}
	if s.frameworkPattern.MatchString(command) {
		base -= 0.2
	}
	
	if s.containsBinaryGarbage(command) {
		base -= 0.4
	}
	
	if s.isMixedContent(command) {
		base -= 0.3
	}
	
	return math.Max(0.0, math.Min(1.0, base))
}

func (s *Scorer) containsBinaryGarbage(command string) bool {
	nonPrintable := 0
	for _, r := range command {
		if r < 0x20 || r > 0x7E {
			nonPrintable++
		}
	}
	
	return float64(nonPrintable)/float64(len(command)) > 0.15
}

func (s *Scorer) isMixedContent(command string) bool {
	binaryIndicators := []string{
		"__TEXT", "__DATA", "__LINKEDIT", "___stderrp", "___stdinp", "___stdoutp",
		"_main", "_system", "_fork", "loader_", "_mh_execute_header",
	}
	
	binaryCount := 0
	for _, indicator := range binaryIndicators {
		if strings.Contains(command, indicator) {
			binaryCount++
		}
	}
	
	return binaryCount >= 4
}

func (s *Scorer) calculateInlineConfidence(features CommandFeatures, command string) float64 {
	if s.isCommonFalsePositive(command) {
		return 0.0
	}
	
	config := newDefaultConfig()
	base := config.MinConfidence
	
	hasOption := regexp.MustCompile(`\s-[a-zA-Z]`).MatchString(command)
	hasPath := regexp.MustCompile(`(^| )/|(\./)`).MatchString(command)
	
	if hasOption {
		base += 0.1
	}
	if features.HasURL {
		base += 0.12
	}
	if hasPath {
		base += 0.08
	}
	
	if s.looksLikeNaturalLanguage(command) {
		base -= 0.3
	}
	
	return math.Min(math.Max(base, 0.0), 0.99)
}

func (s *Scorer) looksLikeNaturalLanguage(command string) bool {
	naturalPatterns := []string{
		"time to", "time unavailable", "time for", "unable to", "failed to", 
		"trying to", "need to", "want to", "have to", "has to", "had to",
		"going to", "used to", "supposed to", "able to", "ready to",
		"node in intrusive list", "is not", "is available", "is unavailable",
		"the file", "the folder", "the system", "each file", "copy the",
		"create the", "launch the", "update the", "settings",
	}
	
	commandLower := strings.ToLower(command)
	for _, pattern := range naturalPatterns {
		if strings.Contains(commandLower, pattern) {
			return true
		}
	}
	
	tokens := strings.Fields(command)
	if len(tokens) >= 3 {
		englishWords := []string{
			"the", "a", "an", "this", "that", "these", "those", "to", "of",
			"is", "are", "was", "were", "be", "been", "being", "have", "has", "had",
			"in", "on", "at", "for", "with", "from", "by", "and", "or", "but",
			"not", "no", "all", "any", "some", "each", "time", "file", "folder",
		}
		
		englishWordCount := 0
		for _, token := range tokens {
			tokenLower := strings.ToLower(strings.Trim(token, ".,!?;:"))
			for _, word := range englishWords {
				if tokenLower == word {
					englishWordCount++
					break
				}
			}
		}
		
		return float64(englishWordCount)/float64(len(tokens)) > 0.5
	}
	
	return false
}

func (s *Scorer) checkSyntax(command string) bool {
	return s.checkQuoteBalance(command) && s.checkParenBalance(command)
}

func (s *Scorer) checkQuoteBalance(command string) bool {
	doubleQuotes := 0
	singleQuotes := 0
	backTicks := 0
	escaped := false
	
	for _, char := range command {
		if escaped {
			escaped = false
			continue
		}
		
		if char == '\\' {
			escaped = true
			continue
		}
		
		switch char {
		case '"':
			if singleQuotes%2 == 0 && backTicks%2 == 0 {
				doubleQuotes++
			}
		case '\'':
			if doubleQuotes%2 == 0 && backTicks%2 == 0 {
				singleQuotes++
			}
		case '`':
			if doubleQuotes%2 == 0 && singleQuotes%2 == 0 {
				backTicks++
			}
		}
	}
	
	return doubleQuotes%2 == 0 && singleQuotes%2 == 0 && backTicks%2 == 0
}

func (s *Scorer) checkParenBalance(command string) bool {
	parens := 0
	doubleQuotes := 0
	singleQuotes := 0
	backTicks := 0
	escaped := false
	
	for _, char := range command {
		if escaped {
			escaped = false
			continue
		}
		
		if char == '\\' {
			escaped = true
			continue
		}
		
		switch char {
		case '"':
			if singleQuotes%2 == 0 && backTicks%2 == 0 {
				doubleQuotes++
			}
		case '\'':
			if doubleQuotes%2 == 0 && backTicks%2 == 0 {
				singleQuotes++
			}
		case '`':
			if doubleQuotes%2 == 0 && singleQuotes%2 == 0 {
				backTicks++
			}
		case '(':
			if doubleQuotes%2 == 0 && singleQuotes%2 == 0 && backTicks%2 == 0 {
				parens++
			}
		case ')':
			if doubleQuotes%2 == 0 && singleQuotes%2 == 0 && backTicks%2 == 0 {
				parens = int(math.Max(float64(parens-1), 0))
			}
		}
	}
	
	return parens == 0
}

func (s *Scorer) isCommonFalsePositive(command string) bool {
	if s.isServiceProtocolDef(command) {
		return true
	}
	
	if s.isBareCommand(command) {
		return true
	}
	
	if s.isBinaryGarbageCommand(command) {
		return true
	}
	
	if s.isIncompleteFragment(command) {
		return true
	}
	
	if s.isNaturalLanguagePhrase(command) {
		return true
	}
	
	return false
}

func (s *Scorer) isServiceProtocolDef(command string) bool {
	servicePattern := regexp.MustCompile(`^\w+\s+\d+/(tcp|udp)(\s+\w+)?$`)
	return servicePattern.MatchString(strings.TrimSpace(command))
}

func (s *Scorer) isBareCommand(command string) bool {
	trimmed := strings.TrimSpace(command)
	tokens := strings.Fields(trimmed)
	
	if len(tokens) == 1 {
		bareCommands := []string{
			"chmod", "mkdir", "rmdir", "timeout", "node", "time", "find",
			"grep", "sed", "awk", "sort", "uniq", "head", "tail", "cat",
			"touch", "cp", "mv", "rm", "ls", "pwd", "cd", "echo",
			"kill", "ps", "top", "which", "whereis", "whoami", "who",
			"date", "cal", "uptime", "df", "du", "free", "uname",
		}
		
		for _, bare := range bareCommands {
			if strings.ToLower(tokens[0]) == bare {
				return true
			}
		}
	}
	
	if len(tokens) == 2 {
		second := tokens[1]
		if strings.HasSuffix(second, ".") || 
		   second == "waiting" || second == "value" || second == "error" ||
		   second == "failed" || second == "success" || second == "done" {
			return true
		}
	}
	
	return false
}

func (s *Scorer) isBinaryGarbageCommand(command string) bool {
	
	binaryKeywords := []string{
		"float32", "float64", "int32", "int64", "uint32", "uint64",
		"forcegc", "allocm", "cpuprof", "memprof", "gctrace",
		"runnable", "syscall", "runknown", "goid", "runtime",
		"January", "February", "March", "April", "May", "June",
		"July", "August", "September", "October", "November", "December",
		"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday",
	}
	
	binaryCount := 0
	commandLower := strings.ToLower(command)
	for _, keyword := range binaryKeywords {
		if strings.Contains(commandLower, strings.ToLower(keyword)) {
			binaryCount++
		}
	}
	
	return binaryCount >= 3
}

func (s *Scorer) isIncompleteFragment(command string) bool {
	
	incompletePatterns := []*regexp.Regexp{
		regexp.MustCompile(`\.\w+\([^)]*$`), // Ends with incomplete function call
		regexp.MustCompile(`\.\w+\.$`),      // Ends with method call and dot
		regexp.MustCompile(`\w+\($`),        // Ends with incomplete parentheses
		regexp.MustCompile(`[{\[]$`),        // Ends with opening brace/bracket
	}
	
	for _, pattern := range incompletePatterns {
		if pattern.MatchString(command) {
			return true
		}
	}
	
	return false
}

func (s *Scorer) isNaturalLanguagePhrase(command string) bool {
	naturalPhrases := []string{
		"timeout waiting for", "node value", "time for", "time to",
		"waiting for command", "command not found", "file not found",
		"permission denied", "access denied", "operation not permitted",
		"no such file", "directory not empty", "disk space",
		"memory usage", "cpu usage", "system load", "network error",
	}
	
	commandLower := strings.ToLower(command)
	for _, phrase := range naturalPhrases {
		if strings.Contains(commandLower, phrase) {
			return true
		}
	}
	
	return false
}

func (s *Scorer) FilterByConfidence(commands []ExtractedCommand, minConfidence float64) []ExtractedCommand {
	var filtered []ExtractedCommand
	
	for _, cmd := range commands {
		if cmd.Confidence >= minConfidence {
			filtered = append(filtered, cmd)
		}
	}
	
	return filtered
}

func (s *Scorer) RankByScore(commands []ExtractedCommand) []ExtractedCommand {
	result := make([]ExtractedCommand, len(commands))
	copy(result, commands)
	
	for i := 0; i < len(result)-1; i++ {
		for j := i + 1; j < len(result); j++ {
			if result[i].Confidence < result[j].Confidence ||
			   (result[i].Confidence == result[j].Confidence && 
			    result[i].FragmentationLevel > result[j].FragmentationLevel) {
				result[i], result[j] = result[j], result[i]
			}
		}
	}
	
	return result
}