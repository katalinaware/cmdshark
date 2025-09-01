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
	
	// Cached config to avoid repeated creation
	cachedConfig      *Config
	
	// Pre-compiled patterns for false positive detection
	binaryPatterns     []*regexp.Regexp
	garbagePatterns    []*regexp.Regexp
	incompletePatterns []*regexp.Regexp
	naturalPatterns    []*regexp.Regexp
	htmlCSSPatterns    []*regexp.Regexp
	configPatterns     []*regexp.Regexp
	programmingPatterns []*regexp.Regexp
	optionPattern      *regexp.Regexp
	pathPattern        *regexp.Regexp
	needsQuotingPattern *regexp.Regexp
	servicePattern     *regexp.Regexp
	upperSeqPattern    *regexp.Regexp
	digitPattern       *regexp.Regexp
	letterPattern      *regexp.Regexp
	specialCharPattern *regexp.Regexp
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
	config := newDefaultConfig()
	return Scorer{
		lexer:            NewLexer(),
		helpPattern:      regexp.MustCompile(`^(?:Usage:|usage:)`),
		copyrightPattern: regexp.MustCompile(`Copyright`),
		frameworkPattern: regexp.MustCompile(`^(?:NS[A-Z]\w+|objc\w+|NSError\w*|CF\w+|kCF\w+)$`),
		urlPattern:       regexp.MustCompile(`https?://`),
		assignPattern:    regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=.*`),
		envRefPattern:    regexp.MustCompile(`\$[{(]?[A-Za-z_][A-Za-z0-9_]*[)}]?`),
		redirectPattern:  regexp.MustCompile(`[><]`),
		cachedConfig:     &config,
		binaryPatterns:   compileBinaryPatterns(),
		garbagePatterns:  compileGarbagePatterns(),
		incompletePatterns: compileIncompletePatterns(),
		naturalPatterns:  compileNaturalPatterns(),
		htmlCSSPatterns:  compileHTMLCSSPatterns(),
		configPatterns:   compileConfigPatterns(),
		programmingPatterns: compileProgrammingPatterns(),
		optionPattern:    regexp.MustCompile(`\s-[a-zA-Z]`),
		pathPattern:      regexp.MustCompile(`(^| )/|(\./)`),
		needsQuotingPattern: regexp.MustCompile(`\s|[|;&><(){}]`),
		servicePattern:   regexp.MustCompile(`^\w+\s+\d+/(tcp|udp)(\s+\w+)?$`),
		upperSeqPattern:  regexp.MustCompile(`[A-Z]{2,}`),
		digitPattern:     regexp.MustCompile(`[0-9]`),
		letterPattern:    regexp.MustCompile(`[a-zA-Z]`),
		specialCharPattern: regexp.MustCompile(`[^a-zA-Z0-9]`),
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
	
	if len(tokens) == 1 {
		return 0.0
	}
	
	if len(tokens) <= 3 && !features.HasPipe && !features.HasURL && !features.HasRedirect {
		base = 0.15
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
		base -= 0.15
	}
	if features.Length < 5 {
		base -= 0.2
	}
	if features.Length > 400 {
		base -= 0.3
	}
	if features.Length > 1000 {
		base -= 0.5
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
	
	if s.isFragmentedBinaryGarbage(command) {
		base -= 0.8
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
	
	base := s.cachedConfig.MinConfidence
	
	hasOption := s.optionPattern.MatchString(command)
	hasPath := s.pathPattern.MatchString(command)
	
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
	return s.servicePattern.MatchString(strings.TrimSpace(command))
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
			"tr", "nc", "sh", "ln", "zip", "xz", "nice", "dash",
		}
		
		for _, bare := range bareCommands {
			if strings.ToLower(tokens[0]) == bare {
				return true
			}
		}
	}
	
	if len(tokens) == 2 {
		first, second := strings.ToLower(tokens[0]), strings.ToLower(tokens[1])
		
		if strings.HasSuffix(second, ".") || strings.HasSuffix(second, ":") ||
		   second == "waiting" || second == "value" || second == "error" ||
		   second == "failed" || second == "success" || second == "done" ||
		   second == "like" || second == "shell" || second == "completion" ||
		   second == "dom" || second == "y" || second == "instead" ||
		   second == "effect" || second == "side" || second == "," ||
		   strings.Contains(second, ".") {
			return true
		}
		
		if (first == "bash" || first == "zsh" || first == "fish") && 
		   (second == "like" || second == ">" || strings.Contains(second, ".")) {
			return true
		}
	}
	
	if len(tokens) == 3 {
		second, third := strings.ToLower(tokens[1]), strings.ToLower(tokens[2])
		if (second == "side" && third == "effect") ||
		   (second == "instead" && strings.Contains(third, ".")) ||
		   (strings.Contains(second, ".") && strings.Contains(third, ":")) {
			return true
		}
	}
	
	if len(tokens) > 8 {
		bareCommandCount := 0
		for _, token := range tokens {
			if s.cachedConfig.Heads[strings.ToLower(token)] {
				bareCommandCount++
			}
		}
		if float64(bareCommandCount)/float64(len(tokens)) > 0.6 {
			return true
		}
	}
	
	return false
}

func (s *Scorer) isBinaryGarbageCommand(command string) bool {
	if s.hasRandomBinaryPatterns(command) {
		return true
	}
	
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
	
	return binaryCount >= 2
}

func (s *Scorer) hasRandomBinaryPatterns(command string) bool {
	for _, pattern := range s.binaryPatterns {
		if pattern.MatchString(command) {
			return true
		}
	}
	
	nonAlpha := 0
	totalChars := 0
	for _, r := range command {
		totalChars++
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == ' ' || r == '-' || r == '_') {
			nonAlpha++
		}
	}
	
	threshold := 0.35
	if totalChars < 20 {
		threshold = 0.25
	}
	
	if totalChars > 5 && float64(nonAlpha)/float64(totalChars) > threshold {
		return true
	}
	
	upperSeqCount := len(s.upperSeqPattern.FindAllString(command, -1))
	if upperSeqCount > 3 {
		return true
	}
	
	if len(command) > 10 {
		randomnessScore := s.calculateRandomnessScore(command)
		if randomnessScore > 0.7 {
			return true
		}
	}
	
	return false
}

func (s *Scorer) calculateRandomnessScore(command string) float64 {
	if len(command) < 5 {
		return 0.0
	}
	
	score := 0.0
	
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
	
	if len(tokens) < 2 {
		return false
	}
	
	garbageTokens := 0
	shortRandomTokens := 0
	
	for _, token := range tokens {
		if s.isGarbageToken(token) {
			garbageTokens++
		}
		
		if len(token) <= 4 && s.hasRandomLookingPattern(token) {
			shortRandomTokens++
		}
	}
	
	garbageRatio := float64(garbageTokens) / float64(len(tokens))
	shortRandomRatio := float64(shortRandomTokens) / float64(len(tokens))
	
	if garbageRatio > 0.6 || shortRandomRatio > 0.5 {
		return true
	}
	
	if strings.HasPrefix(command, "/") && garbageTokens >= 2 {
		return true
	}
	
	return false
}

func (s *Scorer) isGarbageToken(token string) bool {
	if len(token) < 2 {
		return false
	}
	
	for _, pattern := range s.garbagePatterns {
		if pattern.MatchString(token) {
			return true
		}
	}
	
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
	
	specialRatio := float64(special) / float64(total)
	if specialRatio > 0.3 {
		return true
	}
	
	if len(token) <= 4 && alpha > 0 && digit > 0 {
		return true
	}
	
	return false
}

func (s *Scorer) hasRandomLookingPattern(token string) bool {
	if len(token) < 2 {
		return false
	}
	
	caseChanges := 0
	prevUpper := false
	
	for i, r := range token {
		isUpper := r >= 'A' && r <= 'Z'
		if i > 0 && isUpper != prevUpper {
			caseChanges++
		}
		prevUpper = isUpper
	}
	
	if len(token) <= 4 && caseChanges >= 2 {
		return true
	}
	
	hasDigit := s.digitPattern.MatchString(token)
	hasLetter := s.letterPattern.MatchString(token)
	hasSpecial := s.specialCharPattern.MatchString(token)
	
	if len(token) <= 4 && hasDigit && hasLetter {
		return true
	}
	
	if hasSpecial && len(token) <= 6 {
		return true
	}
	
	return false
}

func (s *Scorer) isIncompleteFragment(command string) bool {
	for _, pattern := range s.incompletePatterns {
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
	
	for _, pattern := range s.naturalPatterns {
		if pattern.MatchString(commandLower) {
			return true
		}
	}
	
	return false
}

func (s *Scorer) isHTMLCSSCommand(command string) bool {
	for _, pattern := range s.htmlCSSPatterns {
		if pattern.MatchString(command) {
			return true
		}
	}
	
	return false
}

func (s *Scorer) isConfigurationText(command string) bool {
	for _, pattern := range s.configPatterns {
		if pattern.MatchString(command) {
			return true
		}
	}
	
	return false
}

func (s *Scorer) isCommandList(command string) bool {
	if strings.Contains(command, " ") && len(strings.Fields(command)) > 5 {
		words := strings.Fields(command)
		commandCount := 0
		
		for _, word := range words {
			if s.cachedConfig.Heads[word] {
				commandCount++
			}
		}
		
		if float64(commandCount)/float64(len(words)) > 0.3 {
			return true
		}
	}
	
	return false
}

func (s *Scorer) isProgrammingLanguageFragment(command string) bool {
	for _, pattern := range s.programmingPatterns {
		if pattern.MatchString(command) {
			return true
		}
	}
	
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

// Pre-compiled regex pattern functions
func compileBinaryPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`[/@#$%^&*]{3,}`),
		regexp.MustCompile(`[A-Za-z0-9]{1}[@#$%^&*~` + "`" + `]{2,}[A-Za-z0-9]`),
		regexp.MustCompile(`\w[<>|&$@#%^*~` + "`" + `]{2,}\w`),
		regexp.MustCompile(`[/@]\w{1,3}[@#$%^&*~` + "`" + `|<>]{2,}`),
		regexp.MustCompile(`\b[A-Za-z0-9]{1,2}[|<>&@#$%^*~` + "`" + `]{2,}[A-Za-z0-9]{1,2}\b`),
		regexp.MustCompile(`^/[^/\s]*[@#$%^&*~` + "`" + `|<>=]{2,}`),
		regexp.MustCompile(`\w+[}]{2,}\w*[{]{2,}\w*`),
		regexp.MustCompile(`[A-Z]{1,3}[0-9]{1,3}[A-Z]{1,3}`),
		regexp.MustCompile(`/[a-z0-9]{1,3}\s+[^a-zA-Z\s]{2,}`),
		regexp.MustCompile(`[^a-zA-Z\s]{3,}[\s]+[^a-zA-Z\s]{2,}`),
		regexp.MustCompile(`[*\(\)\[\]\\<>]{2,}`),
		regexp.MustCompile(`[0-9]{2,}[a-zA-Z]{1,2}[0-9a-zA-Z*\^\$\(\)]{2,}`),
		regexp.MustCompile(`\w{1,2}[*\^\$\(\)\[\]\\]{2,}\w{1,2}`),
		regexp.MustCompile(`[/{]\s*[%,\*\^\$\(\)\[\]]{2,}`),
		regexp.MustCompile(`[a-zA-Z]{1,2}[0-9\*\$\^\(\)\[\]\\]{3,}`),
		regexp.MustCompile(`\$[a-zA-Z]{2,}[0-9\*\^\(\)\[\]\\]{2,}`),
		regexp.MustCompile(`["'][a-zA-Z\s]{1,3}[^a-zA-Z\s"']{3,}`),
	}
}

func compileGarbagePatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`^[A-Za-z]{1,3}[0-9]{1,3}[A-Za-z]*$`),
		regexp.MustCompile(`^[A-Za-z]*[|&$#@%^*~` + "`" + `]+[A-Za-z]*$`),
		regexp.MustCompile(`[A-Za-z][0-9][A-Za-z][0-9]`),
		regexp.MustCompile(`^[A-Z]{2,4}$`),
		regexp.MustCompile(`[{}|&$#@%^*~;,` + "`" + `]{2,}`),
		regexp.MustCompile(`^[a-z]{1,2}[,;:|&$@#%^*~` + "`" + `][a-z]*`),
		regexp.MustCompile(`}[0-9a-zA-Z]+[|]`),
		regexp.MustCompile(`[0-9]+[<>` + "`" + `][a-zA-Z]+`),
		regexp.MustCompile(`[A-Za-z]{2,}[0-9]+\)[A-Z]`),
		regexp.MustCompile(`^[a-z]{1}\s+}[0-9a-zA-Z]+`),
		regexp.MustCompile(`[A-Za-z]+[` + "`" + `][0-9][A-Za-z]+`),
		regexp.MustCompile(`\$[a-z][0-9]+\)`),
	}
}

func compileIncompletePatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`\.\w+\([^)]*$`),
		regexp.MustCompile(`\.\w+\.$`),
		regexp.MustCompile(`\w+\($`),
		regexp.MustCompile(`[{\[]$`),
	}
}

func compileNaturalPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`^\w+\s+(to|for|with|on|like|and|or)\s+\w+`),
		regexp.MustCompile(`\w+\s+(may|might|will|can|should)\s+\w+`),
		regexp.MustCompile(`\w+\s+(completion|script)\s+(for|v\d+)`),
		regexp.MustCompile(`(requires|needs)\s+(a\s+)?\w+`),
		regexp.MustCompile(`\w+\s+with\s+no\s+\w+`),
		regexp.MustCompile(`\w+\s+errors?[;,.]`),
		regexp.MustCompile(`(bash|zsh|fish)\s+(like|or|and)`),
		regexp.MustCompile(`\w+\s+(shell|completion)\s+\w+`),
		regexp.MustCompile(`\w+\s+(instead|effect|side|error|issue|problem)`),
		regexp.MustCompile(`\w+\s+[a-z]+\.[a-z]+:`),
		regexp.MustCompile(`^\w+\s+,\s*$`),
	}
}

func compileHTMLCSSPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`^tr\s*>\s*(td|th)`),
		regexp.MustCompile(`^(tr|td|th|div|span|a|p|h[1-6])\s*[>.:]`),
		regexp.MustCompile(`\.(success|warning|info|danger|active|hover)`),
		regexp.MustCompile(`#[a-zA-Z][\w-]*`),
		regexp.MustCompile(`<\/?\w+[^>]*>`),
		regexp.MustCompile(`{[^}]*className[^}]*}`),
		regexp.MustCompile(`(innerHTML|outerHTML|textContent)`),
		regexp.MustCompile(`document\.(getElementById|querySelector)`),
		regexp.MustCompile(`^[\w-]+\s*:\s*[^;]+;?$`),
	}
}

func compileConfigPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`^\w+\s*=\s*[^=]+$`),
		regexp.MustCompile(`^\[[^\]]+\]$`),
		regexp.MustCompile(`^<string>[^<]+</string>$`),
		regexp.MustCompile(`^{{[^}]+}}[^{]*{{[^}]+}}$`),
		regexp.MustCompile(`%[sdqvfgtbcoxX]`),
		regexp.MustCompile(`\$\{[^}]+\}`),
		regexp.MustCompile(`^[\w.]+\s*:\s*\w+$`),
		regexp.MustCompile(`mime\.types`),
		regexp.MustCompile(`/etc/\w+`),
	}
}

func compileProgrammingPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`(begin|end|className|const|var|let|function|return)`),
		regexp.MustCompile(`\w+\([^)]*\)\s*\{`),
		regexp.MustCompile(`\w+\.\w+\([^)]*\)`),
		regexp.MustCompile(`^[a-zA-Z_]\w*\s*=\s*new\s+\w+`),
		regexp.MustCompile(`\w+\[\d+\]`),
		regexp.MustCompile(`\w+\?\.\w+`),
		regexp.MustCompile(`\w+\s*&&\s*\w+`),
		regexp.MustCompile(`^(public|private|protected|static)`),
		regexp.MustCompile(`\w+\.prototype\.\w+`),
		regexp.MustCompile(`^\w+\s*:\s*\w+\s*,`),
		regexp.MustCompile(`^\w+\(\)[\w\s]*$`),
	}
}