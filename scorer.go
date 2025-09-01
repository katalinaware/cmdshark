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
	
	// Never allow single-word commands through
	if len(tokens) == 1 {
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
	
	// Never return single-word commands (including executable paths)
	if len(tokens) == 1 {
		return 0.0 // Filter out all single-word commands
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
	
	// Heavy penalty for fragmented binary garbage patterns
	if s.isFragmentedBinaryGarbage(command) {
		base -= 0.8  // Nearly eliminate these patterns
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
	
	if s.isHTMLCSSCommand(command) {
		return true
	}
	
	if s.isConfigurationText(command) {
		return true
	}
	
	if s.isCommandList(command) {
		return true
	}
	
	if s.isProgrammingLanguageFragment(command) {
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
	
	// Single bare command words that are likely false positives
	if len(tokens) == 1 {
		bareCommands := []string{
			"chmod", "mkdir", "rmdir", "timeout", "node", "time", "find",
			"grep", "sed", "awk", "sort", "uniq", "head", "tail", "cat",
			"touch", "cp", "mv", "rm", "ls", "pwd", "cd", "echo",
			"kill", "ps", "top", "which", "whereis", "whoami", "who",
			"date", "cal", "uptime", "df", "du", "free", "uname",
			"tr", "nc", "sh", "ln", "zip", "xz", "nice", "dash",
		}
		
		for _, bare := range bareCommands {
			if strings.ToLower(tokens[0]) == bare {
				return true
			}
		}
	}
	
	// Command fragments that are documentation/help text
	if len(tokens) == 2 {
		first, second := strings.ToLower(tokens[0]), strings.ToLower(tokens[1])
		
		// Pattern: command + descriptive word
		if strings.HasSuffix(second, ".") || strings.HasSuffix(second, ":") ||
		   second == "waiting" || second == "value" || second == "error" ||
		   second == "failed" || second == "success" || second == "done" ||
		   second == "like" || second == "shell" || second == "completion" ||
		   second == "dom" || second == "y" || second == "instead" ||
		   second == "effect" || second == "side" || second == "," ||
		   strings.Contains(second, ".") {
			return true
		}
		
		// Shell completion patterns
		if (first == "bash" || first == "zsh" || first == "fish") && 
		   (second == "like" || second == ">" || strings.Contains(second, ".")) {
			return true
		}
	}
	
	// Three-word natural language patterns
	if len(tokens) == 3 {
		second, third := strings.ToLower(tokens[1]), strings.ToLower(tokens[2])
		if (second == "side" && third == "effect") ||
		   (second == "instead" && strings.Contains(third, ".")) ||
		   (strings.Contains(second, ".") && strings.Contains(third, ":")) {
			return true
		}
	}
	
	// Sequences of many single-word commands (likely documentation)
	if len(tokens) > 8 {
		config := newDefaultConfig()
		bareCommandCount := 0
		for _, token := range tokens {
			if config.Heads[strings.ToLower(token)] {
				bareCommandCount++
			}
		}
		// If most words are commands, it's likely a command list
		if float64(bareCommandCount)/float64(len(tokens)) > 0.6 {
			return true
		}
	}
	
	return false
}

func (s *Scorer) isBinaryGarbageCommand(command string) bool {
	// Check for random binary-like patterns first
	if s.hasRandomBinaryPatterns(command) {
		return true
	}
	
	// Check for multi-word fragmented binary garbage patterns
	if s.isFragmentedBinaryGarbage(command) {
		return true
	}
	
	binaryKeywords := []string{
		"float32", "float64", "int32", "int64", "uint32", "uint64",
		"forcegc", "allocm", "cpuprof", "memprof", "gctrace",
		"runnable", "syscall", "runknown", "goid", "runtime",
		"January", "February", "March", "April", "May", "June",
		"July", "August", "September", "October", "November", "December",
		"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday",
		"ParseUint", "complex64", "interface", "invalid", "reflect",
		"funcargs", "CallSlice", "InterfaceData", "rwxrwxrwx", "timer",
		"pollCache", "profBlock", "stackpool", "hchanLeaf", "wbufSpans",
		"mSpanDead", "inittrace", "scavtrace", "panicwait", "preempted",
		"coroutine", "copystack", "GOTOOLDIR", "unmarked", "overflow",
		"packing", "uint8", "slog.Kind", "wiretetype", "protobuf",
		"editions", "defaults", "unmarshal", "byteordermark", "fastinfoset",
	}
	
	binaryCount := 0
	commandLower := strings.ToLower(command)
	for _, keyword := range binaryKeywords {
		if strings.Contains(commandLower, strings.ToLower(keyword)) {
			binaryCount++
		}
	}
	
	return binaryCount >= 2  // Reduced threshold for better detection
}

func (s *Scorer) hasRandomBinaryPatterns(command string) bool {
	// Look for patterns that suggest random binary data
	binaryPatterns := []*regexp.Regexp{
		regexp.MustCompile(`[/@#$%^&*]{3,}`),                      // Multiple special chars
		regexp.MustCompile(`[A-Za-z0-9]{1}[@#$%^&*~`+"`"+`]{2,}[A-Za-z0-9]`), // Char-special-char patterns
		regexp.MustCompile(`\w[<>|&$@#%^*~`+"`"+`]{2,}\w`),       // Embedded binary-like chars
		regexp.MustCompile(`[/@]\w{1,3}[@#$%^&*~`+"`"+`|<>]{2,}`), // Starts with / or @, short text, then specials
		regexp.MustCompile(`\b[A-Za-z0-9]{1,2}[|<>&@#$%^*~`+"`"+`]{2,}[A-Za-z0-9]{1,2}\b`), // Short-special-short
		regexp.MustCompile(`^/[^/\s]*[@#$%^&*~`+"`"+`|<>=]{2,}`), // Path-like with specials
		regexp.MustCompile(`\w+[}]{2,}\w*[{]{2,}\w*`),            // Multiple braces pattern
		regexp.MustCompile(`[A-Z]{1,3}[0-9]{1,3}[A-Z]{1,3}`),     // Caps-digits-caps (like "ACB", "T26")
		
		// Enhanced patterns for the new examples
		regexp.MustCompile(`/[a-z0-9]{1,3}\s+[^a-zA-Z\s]{2,}`),   // "/l] '[S" pattern
		regexp.MustCompile(`[^a-zA-Z\s]{3,}[\s]+[^a-zA-Z\s]{2,}`), // Multiple non-alpha sequences
		regexp.MustCompile(`[*\(\)\[\]\\<>]{2,}`),                 // Multiple brackets/parens/backslashes
		regexp.MustCompile(`[0-9]{2,}[a-zA-Z]{1,2}[0-9a-zA-Z*\^\$\(\)]{2,}`), // "89 7*1k2i" pattern
		regexp.MustCompile(`\w{1,2}[*\^\$\(\)\[\]\\]{2,}\w{1,2}`), // Short-special-short with specific chars
		regexp.MustCompile(`[/{]\s*[%,\*\^\$\(\)\[\]]{2,}`),       // Starts with / or { followed by specials
		regexp.MustCompile(`[a-zA-Z]{1,2}[0-9\*\$\^\(\)\[\]\\]{3,}`), // Letter followed by numbers/specials
		regexp.MustCompile(`\$[a-zA-Z]{2,}[0-9\*\^\(\)\[\]\\]{2,}`), // $variable followed by garbage
		regexp.MustCompile(`["'][a-zA-Z\s]{1,3}[^a-zA-Z\s"']{3,}`), // Quoted short text followed by garbage
	}
	
	for _, pattern := range binaryPatterns {
		if pattern.MatchString(command) {
			return true
		}
	}
	
	// Check for high ratio of non-alphabetic characters (more aggressive)
	nonAlpha := 0
	totalChars := 0
	for _, r := range command {
		totalChars++
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == ' ' || r == '-' || r == '_') {
			nonAlpha++
		}
	}
	
	// Lower threshold for shorter commands, higher for longer ones
	threshold := 0.35
	if totalChars < 20 {
		threshold = 0.25 // More aggressive for short commands
	}
	
	if totalChars > 5 && float64(nonAlpha)/float64(totalChars) > threshold {
		return true
	}
	
	// Check for too many uppercase sequences
	upperSeqCount := len(regexp.MustCompile(`[A-Z]{2,}`).FindAllString(command, -1))
	if upperSeqCount > 3 {
		return true
	}
	
	// Check for mixed case randomness patterns
	if len(command) > 10 {
		randomnessScore := s.calculateRandomnessScore(command)
		if randomnessScore > 0.7 {
			return true
		}
	}
	
	return false
}

// Helper function to calculate randomness score
func (s *Scorer) calculateRandomnessScore(command string) float64 {
	if len(command) < 5 {
		return 0.0
	}
	
	score := 0.0
	
	// Check for alternating case patterns
	caseChanges := 0
	prevUpper := false
	for i, r := range command {
		if r >= 'A' && r <= 'Z' {
			if i > 0 && !prevUpper {
				caseChanges++
			}
			prevUpper = true
		} else if r >= 'a' && r <= 'z' {
			if i > 0 && prevUpper {
				caseChanges++
			}
			prevUpper = false
		}
	}
	
	if caseChanges > len(command)/3 {
		score += 0.3
	}
	
	// Check for random-looking character sequences
	specialCount := 0
	digitCount := 0
	for _, r := range command {
		if r >= '0' && r <= '9' {
			digitCount++
		} else if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == ' ' || r == '-' || r == '_') {
			specialCount++
		}
	}
	
	specialRatio := float64(specialCount) / float64(len(command))
	digitRatio := float64(digitCount) / float64(len(command))
	
	if specialRatio > 0.2 {
		score += specialRatio
	}
	if digitRatio > 0.3 {
		score += digitRatio * 0.5
	}
	
	return score
}

func (s *Scorer) isFragmentedBinaryGarbage(command string) bool {
	tokens := strings.Fields(command)
	
	// Need at least 2 tokens to be fragmented
	if len(tokens) < 2 {
		return false
	}
	
	// Check for patterns typical of fragmented binary garbage
	garbageTokens := 0
	shortRandomTokens := 0
	
	for _, token := range tokens {
		// Count tokens that look like random binary garbage
		if s.isGarbageToken(token) {
			garbageTokens++
		}
		
		// Count short tokens with mixed case/special chars
		if len(token) <= 4 && s.hasRandomLookingPattern(token) {
			shortRandomTokens++
		}
	}
	
	// If most tokens look like garbage, it's likely fragmented binary data
	garbageRatio := float64(garbageTokens) / float64(len(tokens))
	shortRandomRatio := float64(shortRandomTokens) / float64(len(tokens))
	
	// Very aggressive filtering for fragmented patterns
	if garbageRatio > 0.6 || shortRandomRatio > 0.5 {
		return true
	}
	
	// Special case: starts with / and has multiple garbage-looking tokens
	if strings.HasPrefix(command, "/") && garbageTokens >= 2 {
		return true
	}
	
	return false
}

func (s *Scorer) isGarbageToken(token string) bool {
	if len(token) < 2 {
		return false
	}
	
	// Patterns that indicate a garbage token
	garbagePatterns := []*regexp.Regexp{
		regexp.MustCompile(`^[A-Za-z]{1,3}[0-9]{1,3}[A-Za-z]*$`),     // Letters+digits pattern like "Za", "QHI"
		regexp.MustCompile(`^[A-Za-z]*[|&$#@%^*~`+"`"+`]+[A-Za-z]*$`), // Contains special chars like "r,vm", "ap;r"
		regexp.MustCompile(`[A-Za-z][0-9][A-Za-z][0-9]`),             // Alternating letters/digits
		regexp.MustCompile(`^[A-Z]{2,4}$`),                           // Short all-caps like "QHI", "Kbhrr"
		regexp.MustCompile(`[{}|&$#@%^*~;,`+"`"+`]{2,}`),             // Multiple special chars
		regexp.MustCompile(`^[a-z]{1,2}[,;:|&$@#%^*~`+"`"+`][a-z]*`), // Short word + special
		regexp.MustCompile(`}[0-9a-zA-Z]+[|]`),                       // Patterns like "}9uyd9O|"
		regexp.MustCompile(`[0-9]+[<>`+"`"+`][a-zA-Z]+`),             // Patterns like "6<T`"
		regexp.MustCompile(`[A-Za-z]{2,}[0-9]+\)[A-Z]`),              // Patterns like "l1)M"
		regexp.MustCompile(`^[a-z]{1}\s+}[0-9a-zA-Z]+`),              // Patterns like "y }9uyd9O"
		regexp.MustCompile(`[A-Za-z]+[`+"`"+`][0-9][A-Za-z]+`),       // Backtick patterns like "T`1XY"
		regexp.MustCompile(`\$[a-z][0-9]+\)`),                        // Patterns like "$l1)"
	}
	
	for _, pattern := range garbagePatterns {
		if pattern.MatchString(token) {
			return true
		}
	}
	
	// Check character composition
	alpha := 0
	digit := 0
	special := 0
	
	for _, r := range token {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			alpha++
		} else if r >= '0' && r <= '9' {
			digit++
		} else {
			special++
		}
	}
	
	total := alpha + digit + special
	if total == 0 {
		return false
	}
	
	// Token is garbage if it has high special char ratio or mixed composition
	specialRatio := float64(special) / float64(total)
	if specialRatio > 0.3 {
		return true
	}
	
	// Mixed short tokens with digits and letters are suspicious
	if len(token) <= 4 && alpha > 0 && digit > 0 {
		return true
	}
	
	return false
}

func (s *Scorer) hasRandomLookingPattern(token string) bool {
	if len(token) < 2 {
		return false
	}
	
	// Look for patterns that suggest randomness
	caseChanges := 0
	prevUpper := false
	
	for i, r := range token {
		isUpper := r >= 'A' && r <= 'Z'
		if i > 0 && isUpper != prevUpper {
			caseChanges++
		}
		prevUpper = isUpper
	}
	
	// Frequent case changes in short tokens suggest randomness
	if len(token) <= 4 && caseChanges >= 2 {
		return true
	}
	
	// Contains numbers mixed with letters
	hasDigit := regexp.MustCompile(`[0-9]`).MatchString(token)
	hasLetter := regexp.MustCompile(`[a-zA-Z]`).MatchString(token)
	hasSpecial := regexp.MustCompile(`[^a-zA-Z0-9]`).MatchString(token)
	
	if len(token) <= 4 && hasDigit && hasLetter {
		return true
	}
	
	if hasSpecial && len(token) <= 6 {
		return true
	}
	
	return false
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
		"may print some errors", "shell script", "completion for",
		"like bash", "like zsh", "like fish", "completion v",
		"or zsh", "and zsh", "shell completion", "file filtering",
		"requires a glob", "to match on", "trigger file",
		"needs --flag", "prefix match", "with no prefix",
		"node prefix length", "glob pattern", "some errors",
		"besides,", "print some", "completion needs",
		"zsh requires", "fish shell", "bash or",
	}
	
	commandLower := strings.ToLower(command)
	for _, phrase := range naturalPhrases {
		if strings.Contains(commandLower, phrase) {
			return true
		}
	}
	
	// Enhanced pattern-based detection
	naturalPatterns := []*regexp.Regexp{
		regexp.MustCompile(`^\w+\s+(to|for|with|on|like|and|or)\s+\w+`),  // "command to/for/with/on something"
		regexp.MustCompile(`\w+\s+(may|might|will|can|should)\s+\w+`),    // Modal verbs
		regexp.MustCompile(`\w+\s+(completion|script)\s+(for|v\d+)`),      // Completion scripts
		regexp.MustCompile(`(requires|needs)\s+(a\s+)?\w+`),               // "requires/needs something"
		regexp.MustCompile(`\w+\s+with\s+no\s+\w+`),                      // "something with no something"
		regexp.MustCompile(`\w+\s+errors?[;,.]`),                         // Error messages
		regexp.MustCompile(`(bash|zsh|fish)\s+(like|or|and)`),            // Shell references
		regexp.MustCompile(`\w+\s+(shell|completion)\s+\w+`),             // Shell/completion references
		regexp.MustCompile(`\w+\s+(instead|effect|side|error|issue|problem)`), // Natural language words
		regexp.MustCompile(`\w+\s+[a-z]+\.[a-z]+:`),                      // Technical terms like "instead.asn1:"
		regexp.MustCompile(`^\w+\s+,\s*$`),                               // Commands ending with comma like "tr ,"
	}
	
	for _, pattern := range naturalPatterns {
		if pattern.MatchString(commandLower) {
			return true
		}
	}
	
	return false
}

func (s *Scorer) isHTMLCSSCommand(command string) bool {
	htmlCSSPatterns := []*regexp.Regexp{
		regexp.MustCompile(`^tr\s*>\s*(td|th)`),                    // CSS table selectors
		regexp.MustCompile(`^(tr|td|th|div|span|a|p|h[1-6])\s*[>.:]`), // HTML/CSS selectors
		regexp.MustCompile(`\.(success|warning|info|danger|active|hover)`), // CSS classes
		regexp.MustCompile(`#[a-zA-Z][\w-]*`),                      // CSS IDs
		regexp.MustCompile(`<\/?\w+[^>]*>`),                        // HTML tags
		regexp.MustCompile(`{[^}]*className[^}]*}`),                // JSX className
		regexp.MustCompile(`(innerHTML|outerHTML|textContent)`),    // DOM properties
		regexp.MustCompile(`document\.(getElementById|querySelector)`), // DOM methods
		regexp.MustCompile(`^[\w-]+\s*:\s*[^;]+;?$`),              // CSS property
	}
	
	for _, pattern := range htmlCSSPatterns {
		if pattern.MatchString(command) {
			return true
		}
	}
	
	return false
}

func (s *Scorer) isConfigurationText(command string) bool {
	configPatterns := []*regexp.Regexp{
		regexp.MustCompile(`^\w+\s*=\s*[^=]+$`),                   // Key-value pairs
		regexp.MustCompile(`^\[[^\]]+\]$`),                        // INI sections
		regexp.MustCompile(`^<string>[^<]+</string>$`),            // XML config
		regexp.MustCompile(`^{{[^}]+}}[^{]*{{[^}]+}}$`),          // Template syntax
		regexp.MustCompile(`%[sdqvfgtbcoxX]`),                     // Printf format strings
		regexp.MustCompile(`\$\{[^}]+\}`),                         // Variable substitution
		regexp.MustCompile(`^[\w.]+\s*:\s*\w+$`),                  // YAML-like
		regexp.MustCompile(`mime\.types`),                          // MIME config
		regexp.MustCompile(`/etc/\w+`),                            // Config file paths
	}
	
	for _, pattern := range configPatterns {
		if pattern.MatchString(command) {
			return true
		}
	}
	
	return false
}

func (s *Scorer) isCommandList(command string) bool {
	// Detect command lists that are just documentation
	if strings.Contains(command, " ") && len(strings.Fields(command)) > 5 {
		words := strings.Fields(command)
		commandCount := 0
		config := newDefaultConfig()
		
		for _, word := range words {
			if config.Heads[word] {
				commandCount++
			}
		}
		
		// If more than 30% of words are commands, it's likely a command list
		if float64(commandCount)/float64(len(words)) > 0.3 {
			return true
		}
	}
	
	return false
}

func (s *Scorer) isProgrammingLanguageFragment(command string) bool {
	programmingPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(begin|end|className|const|var|let|function|return)`), // JS/Generic keywords
		regexp.MustCompile(`\w+\([^)]*\)\s*\{`),                   // Function definitions
		regexp.MustCompile(`\w+\.\w+\([^)]*\)`),                   // Method calls
		regexp.MustCompile(`^[a-zA-Z_]\w*\s*=\s*new\s+\w+`),      // Object instantiation
		regexp.MustCompile(`\w+\[\d+\]`),                          // Array access
		regexp.MustCompile(`\w+\?\.\w+`),                          // Optional chaining
		regexp.MustCompile(`\w+\s*&&\s*\w+`),                      // Logical operators (when not shell)
		regexp.MustCompile(`^(public|private|protected|static)`),  // Access modifiers
		regexp.MustCompile(`\w+\.prototype\.\w+`),                 // Prototype methods
		regexp.MustCompile(`^\w+\s*:\s*\w+\s*,`),                  // Object properties
		regexp.MustCompile(`^\w+\(\)[\w\s]*$`),                    // Function call without args
	}
	
	for _, pattern := range programmingPatterns {
		if pattern.MatchString(command) {
			return true
		}
	}
	
	// Check for JavaScript object notation
	if strings.Contains(command, "{") && strings.Contains(command, "}") && 
	   (strings.Contains(command, "className") || strings.Contains(command, "begin:") || 
	    strings.Contains(command, "end:") || strings.Contains(command, "relevance:")) {
		return true
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