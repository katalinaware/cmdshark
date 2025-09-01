package cmdshark

import (
	"regexp"
	"strings"
)

type CommandExtractor struct {
	config Config
	lexer  Lexer
	parser Parser
	scorer Scorer
}

type ExtractedCommand struct {
	Command            string   `json:"command"`
	Confidence         float64  `json:"confidence"`
	FragmentationLevel int      `json:"fragmentation_level"`
	Methods            []string `json:"methods"`
	SyntaxOK           bool     `json:"syntax_ok"`
}

type Config struct {
	MaxWindow              int                        `json:"max_window"`
	MaxJoinChars          int                        `json:"max_join_chars"`
	Heads                 map[string]bool            `json:"heads"`
	OptionArity           map[string]map[string]int  `json:"option_arity"`
	Dedupe                bool                       `json:"dedupe"`
	MinConfidence         float64                    `json:"min_confidence"`
	MaxFragmentsTotal     int                        `json:"max_fragments_total"`
	MaxFragmentsPerSegment int                       `json:"max_fragments_per_segment"`
}

func NewCommandExtractor() *CommandExtractor {
	return &CommandExtractor{
		config: newDefaultConfig(),
		lexer:  NewLexer(),
		parser: NewParser(),
		scorer: NewScorer(),
	}
}

func (e *CommandExtractor) ExtractFromBlob(text string) []ExtractedCommand {
	commands := e.extractFromCleanLines(text)
	
	if len(commands) < 2 {
		segments := e.lexer.SplitStatements(text)
		for _, segment := range segments {
			if cmd := e.extractFromSegment(segment); cmd != nil {
				commands = append(commands, *cmd)
			}
		}
	}
	
	return e.dedupe(commands)
}

func (e *CommandExtractor) extractFromCleanLines(text string) []ExtractedCommand {
	var commands []ExtractedCommand
	
	
	lines := strings.Split(text, "\n")
	
	if len(lines) == 1 && len(lines[0]) > 200 {
		lines = e.splitLongLine(lines[0])
	}
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || len(line) < 5 {
			continue
		}
		
		lineCommands := e.extractCommandsFromLine(line)
		commands = append(commands, lineCommands...)
	}
	
	return commands
}

func (e *CommandExtractor) splitLongLine(line string) []string {
	var parts []string
	
	config := newDefaultConfig()
	words := strings.Fields(line)
	
	var currentPart []string
	
	for i, word := range words {
		if config.Heads[word] && len(currentPart) > 0 {
			if len(currentPart) > 0 {
				parts = append(parts, strings.Join(currentPart, " "))
			}
			currentPart = []string{word}
		} else {
			currentPart = append(currentPart, word)
		}
		
		if i > 0 && e.lexer.IsNoiseToken(word) && e.lexer.IsNoiseToken(words[i-1]) {
			if len(currentPart) > 2 {
				parts = append(parts, strings.Join(currentPart[:len(currentPart)-2], " "))
				currentPart = currentPart[len(currentPart)-2:]
			}
		}
	}
	
	if len(currentPart) > 0 {
		parts = append(parts, strings.Join(currentPart, " "))
	}
	
	return parts
}

func (e *CommandExtractor) extractCommandsFromLine(line string) []ExtractedCommand {
	var commands []ExtractedCommand
	
	if e.lexer.IsNoiseToken(line) {
		return commands
	}
	
	if !e.containsCommandHead(line) {
		return commands
	}
	
	if e.isLineTooMixed(line) {
		return commands
	}
	
	if cmd := e.extractFromSegment(line); cmd != nil {
		commands = append(commands, *cmd)
	}
	
	return commands
}

func (e *CommandExtractor) containsCommandHead(line string) bool {
	tokens := strings.Fields(line)
	for _, token := range tokens {
		if e.lexer.IsHead(token) {
			return true
		}
	}
	return false
}

func (e *CommandExtractor) isLineTooMixed(line string) bool {
	hasCommand := e.containsCommandHead(line)
	binarySymbols := []string{"__TEXT", "__DATA", "_main", "_system", "___stderr", "loader_"}
	
	symbolCount := 0
	for _, symbol := range binarySymbols {
		if strings.Contains(line, symbol) {
			symbolCount++
		}
	}
	
	return hasCommand && symbolCount >= 4
}

func (e *CommandExtractor) ExtractCommands(rawStrings []string) []ExtractedCommand {
	normalized := e.lexer.NormalizeStrings(rawStrings)
	
	streamCommands := e.extractFromStream(normalized)
	blobCommands := e.extractFromBlobs(normalized)
	
	allCommands := append(streamCommands, blobCommands...)
	return e.dedupe(allCommands)
}

func (e *CommandExtractor) extractFromSegment(segment string) *ExtractedCommand {
	startPos := e.lexer.FindHeadStart(segment)
	if startPos == -1 {
		return nil
	}
	
	cmd := e.lexer.NormalizeWhitespace(segment[startPos:])
	
	if e.isLikelyFalsePositive(cmd) {
		return nil
	}
	
	confidence := e.scorer.ScoreInlineCommand(cmd)
	
	if confidence < e.config.MinConfidence {
		return nil
	}
	
	return &ExtractedCommand{
		Command:            cmd,
		Confidence:         confidence,
		FragmentationLevel: 1,
		Methods:           []string{"intra-line segmentation", "head-anchored slice"},
		SyntaxOK:          true,
	}
}

func (e *CommandExtractor) isLikelyFalsePositive(cmd string) bool {
	if len(cmd) > 800 {  // Increased from 500
		return true
	}
	
	if e.lexer.HasTooMuchBinaryData(cmd) {
		return true
	}
	
	if e.isJustLibraryPath(cmd) {
		return true
	}
	
	if e.isNaturalLanguageSentence(cmd) {
		return true
	}
	
	sections := []string{"__TEXT", "__DATA", "__LINKEDIT", "_main", "_system", "___stderrp", "___stdinp", "___stdoutp"}
	sectionCount := 0
	for _, section := range sections {
		if strings.Contains(cmd, section) {
			sectionCount++
		}
	}
	
	if sectionCount >= 5 {  // Increased from 3
		return true
	}
	
	tokens := strings.Fields(cmd)
	if len(tokens) > 30 {  // Increased from 20
		commandTokens := 0
		for _, token := range tokens {
			if e.lexer.IsHead(token) || strings.HasPrefix(token, "-") || 
			   strings.Contains(token, "http") || strings.Contains(token, ".") ||
			   strings.Contains(token, "/") {  // Added path-like tokens
				commandTokens++
			}
		}
		
		if float64(commandTokens)/float64(len(tokens)) < 0.15 {  // Reduced from 0.2
			return true
		}
	}
	
	return false
}

func (e *CommandExtractor) isNaturalLanguageSentence(cmd string) bool {
	if len(strings.Fields(cmd)) < 3 {
		return false
	}
	
	naturalLanguagePatterns := []string{
		"time to",
		"time unavailable",
		"time for",
		"unable to",
		"failed to",
		"trying to",
		"need to",
		"want to",
		"how to",
		"where to",
		"when to",
		"what to",
		"why to",
		"in order to",
		"going to",
		"have to",
		"has to",
		"had to",
		"should be",
		"could be",
		"would be",
		"might be",
		"may be",
		"will be",
		"can be",
		"must be",
		"seems to",
		"appears to",
		"tends to",
		"used to",
		"supposed to",
		"able to",
		"ready to",
		"free to",
		"easy to",
		"hard to",
		"difficult to",
		"possible to",
		"impossible to",
		"necessary to",
		"important to",
		"enough to",
		"too many",
		"too much",
		"too few",
		"too little",
		"a lot of",
		"lots of",
		"plenty of",
		"kind of",
		"sort of",
		"type of",
		"part of",
		"some of",
		"most of",
		"all of",
		"none of",
		"one of",
		"each of",
		"both of",
		"either of",
		"neither of",
		"instead of",
		"because of",
		"in spite of",
		"on behalf of",
		"by means of",
		"with respect to",
		"in addition to",
		"as well as",
		"along with",
		"together with",
		"in case of",
		"in front of",
		"on top of",
		"at the end of",
		"at the beginning of",
		"in the middle of",
		"node in intrusive list",
		"list is empty",
		"is not empty",
		"is available",
		"is unavailable",
		"is ready",
		"is not ready",
		"is complete",
		"is incomplete",
		"is successful",
		"is unsuccessful",
		"is valid",
		"is invalid",
		"is enabled",
		"is disabled",
	}
	
	cmdLower := strings.ToLower(cmd)
	for _, pattern := range naturalLanguagePatterns {
		if strings.Contains(cmdLower, pattern) {
			return true
		}
	}
	
	tokens := strings.Fields(cmd)
	if len(tokens) >= 4 {
		englishWords := []string{
			"the", "a", "an", "this", "that", "these", "those",
			"is", "are", "was", "were", "be", "been", "being",
			"have", "has", "had", "do", "does", "did", "will", "would",
			"can", "could", "should", "may", "might", "must",
			"in", "on", "at", "by", "for", "with", "from", "to", "of",
			"and", "or", "but", "so", "if", "when", "where", "why", "how",
			"not", "no", "yes", "all", "any", "some", "many", "much",
			"very", "quite", "rather", "really", "just", "only", "also",
			"here", "there", "now", "then", "today", "yesterday", "tomorrow",
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
		
		if float64(englishWordCount)/float64(len(tokens)) > 0.4 {
			return true
		}
	}
	
	firstToken := strings.ToLower(tokens[0])
	naturalLanguageStarters := []string{
		"time", "unable", "failed", "trying", "need", "want", "how", "where", 
		"when", "what", "why", "going", "have", "has", "had", "should", 
		"could", "would", "might", "may", "will", "can", "must", "seems", 
		"appears", "tends", "used", "supposed", "able", "ready", "free", 
		"easy", "hard", "difficult", "possible", "impossible", "necessary", 
		"important", "enough", "too", "a", "lots", "plenty", "kind", "sort", 
		"type", "part", "some", "most", "all", "none", "one", "each", "both", 
		"either", "neither", "instead", "because", "in", "on", "by", "with", 
		"from", "node", "list", "this", "that", "these", "those", "there",
	}
	
	for _, starter := range naturalLanguageStarters {
		if firstToken == starter && len(tokens) > 2 {
			hasCommandStructure := false
			for _, token := range tokens[1:] {
				if strings.HasPrefix(token, "-") || strings.Contains(token, "/") || 
				   strings.Contains(token, "http") || strings.Contains(token, "=") {
					hasCommandStructure = true
					break
				}
			}
			if !hasCommandStructure {
				return true
			}
		}
	}
	
	return false
}

func (e *CommandExtractor) isJustLibraryPath(cmd string) bool {
	cmd = strings.TrimSpace(cmd)
	
	tokens := strings.Fields(cmd)
	if len(tokens) != 1 {
		return false // Has multiple tokens, might be a real command
	}
	
	path := tokens[0]
	
	libraryPatterns := []string{
		"/usr/lib/",
		"/System/Library/",
		"/Library/Frameworks/",
		"/Applications/",
		".dylib",
		".framework",
		".bundle",
	}
	
	for _, pattern := range libraryPatterns {
		if strings.Contains(path, pattern) {
			return true
		}
	}
	
	if strings.HasPrefix(path, "/usr/") || strings.HasPrefix(path, "/System/") {
		if !strings.Contains(path, "/bin/") && !strings.Contains(path, "/sbin/") {
			return true
		}
	}
	
	return false
}

func (e *CommandExtractor) extractFromStream(rows []string) []ExtractedCommand {
	seeds := e.parser.FindSeedPositions(rows)
	commands := make([]ExtractedCommand, 0, len(seeds))
	
	for _, pos := range seeds {
		result := e.parser.ExpandFromPosition(rows, pos, e.config)
		if len(result.Tokens) == 0 {
			continue
		}
		
		confidence, syntaxOK := e.scorer.ScoreCandidate(result.Tokens, result.Methods)
		if confidence >= e.config.MinConfidence {
			commands = append(commands, ExtractedCommand{
				Command:            strings.Join(result.Tokens, " "),
				Confidence:         confidence,
				FragmentationLevel: len(result.Indices),
				Methods:           result.Methods,
				SyntaxOK:          syntaxOK,
			})
		}
	}
	
	return commands
}

func (e *CommandExtractor) extractFromBlobs(rows []string) []ExtractedCommand {
	var commands []ExtractedCommand
	for _, row := range rows {
		commands = append(commands, e.ExtractFromBlob(row)...)
	}
	return commands
}

func (e *CommandExtractor) dedupe(commands []ExtractedCommand) []ExtractedCommand {
	if !e.config.Dedupe {
		return commands
	}
	
	seen := make(map[string]*ExtractedCommand)
	normalizeSpace := regexp.MustCompile(`\s+`)
	
	for i := range commands {
		key := normalizeSpace.ReplaceAllString(strings.TrimSpace(commands[i].Command), " ")
		if existing, exists := seen[key]; !exists || commands[i].Confidence > existing.Confidence {
			seen[key] = &commands[i]
		}
	}
	
	result := make([]ExtractedCommand, 0, len(seen))
	for _, cmd := range seen {
		result = append(result, *cmd)
	}
	
	return result
}

func newDefaultConfig() Config {
	heads := map[string]bool{
		"sh": true, "bash": true, "zsh": true, "ksh": true, "fish": true, "dash": true,
		"sudo": true, "env": true, "nohup": true, "nice": true, "time": true, "timeout": true,
		"curl": true, "wget": true, "nc": true, "ncat": true, "telnet": true, "openssl": true,
		"scp": true, "sftp": true, "ps": true, "kill": true, "killall": true, "pkill": true,
		"pgrep": true, "launchctl": true, "osascript": true, "sysctl": true, "ls": true,
		"cp": true, "mv": true, "rm": true, "mkdir": true, "rmdir": true, "chmod": true,
		"chown": true, "ln": true, "tar": true, "gzip": true, "gunzip": true, "xz": true,
		"unzip": true, "zip": true, "grep": true, "egrep": true, "fgrep": true, "sed": true,
		"awk": true, "tr": true, "cut": true, "sort": true, "uniq": true, "python": true,
		"python3": true, "perl": true, "ruby": true, "node": true, "npm": true, "yarn": true,
		"swift": true, "spctl": true, "codesign": true, "xattr": true, "plutil": true,
		"ditto": true, "hdiutil": true, "installer": true,
	}

	optionArity := map[string]map[string]int{
		"curl": {
			"-H": 1, "--header": 1, "-d": 1, "--data": 1, "-o": 1, "--output": 1,
			"-X": 1, "--request": 1, "-u": 1, "--user": 1, "--url": 1, 
			"--max-time": 1, "-F": 1,
		},
		"bash": {"-c": 1}, "sh": {"-c": 1}, "zsh": {"-c": 1},
		"osascript": {"-e": 1},
		"grep": {"-e": 1, "-f": 1, "--regexp": 1, "--file": 1},
		"sed": {"-e": 1, "-f": 1},
		"tar": {"-f": 1},
	}

	return Config{
		MaxWindow:              12,
		MaxJoinChars:          600,
		Heads:                 heads,
		OptionArity:           optionArity,
		Dedupe:                true,
		MinConfidence:         0.45,
		MaxFragmentsTotal:     24,
		MaxFragmentsPerSegment: 4,
	}
}