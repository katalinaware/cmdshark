package cmdshark

import (
	"regexp"
	"strings"
	"unicode"
)

type Lexer struct {
	printableFilter    *regexp.Regexp
	pathHeadPattern    *regexp.Regexp
	whitespacePattern  *regexp.Regexp
}

func NewLexer() Lexer {
	return Lexer{
		printableFilter:   regexp.MustCompile(`[\x20-\x7E]+`),
		pathHeadPattern:   regexp.MustCompile(`(?:/usr/\S+|/bin/\S+|/sbin/\S+)`),
		whitespacePattern: regexp.MustCompile(`\s+`),
	}
}

func (l *Lexer) NormalizeStrings(rows []string) []string {
	var result []string
	
	for _, raw := range rows {
		if raw == "" {
			continue
		}
		
		parts := l.printableFilter.FindAllString(raw, -1)
		if len(parts) == 0 {
			continue
		}
		
		text := strings.TrimSpace(strings.Join(parts, ""))
		if text == "" {
			continue
		}
		
		result = append(result, text)
	}
	
	return result
}

func (l *Lexer) SplitStatements(s string) []string {
	var parts []string
	var buf strings.Builder
	
	inDoubleQuote := false
	inSingleQuote := false
	i := 0
	runes := []rune(s)
	
	for i < len(runes) {
		ch := runes[i]
		
		switch {
		case ch == '"' && !inSingleQuote:
			inDoubleQuote = !inDoubleQuote
			buf.WriteRune(ch)
			
		case ch == '\'' && !inDoubleQuote:
			inSingleQuote = !inSingleQuote
			buf.WriteRune(ch)
			
		case !inDoubleQuote && !inSingleQuote:
			if ch == '\n' || ch == ';' {
				if buf.Len() > 0 {
					parts = append(parts, strings.TrimSpace(buf.String()))
					buf.Reset()
				}
				i++
				continue
			}
			
			if (ch == '&' || ch == '|') && i+1 < len(runes) && runes[i+1] == ch {
				if buf.Len() > 0 {
					parts = append(parts, strings.TrimSpace(buf.String()))
					buf.Reset()
				}
				i += 2
				continue
			}
			
			buf.WriteRune(ch)
			
		default:
			buf.WriteRune(ch)
		}
		i++
	}
	
	if buf.Len() > 0 {
		parts = append(parts, strings.TrimSpace(buf.String()))
	}
	
	var nonEmpty []string
	for _, part := range parts {
		if part != "" {
			nonEmpty = append(nonEmpty, part)
		}
	}
	
	return nonEmpty
}

func (l *Lexer) FindHeadStart(segment string) int {
	tokens := strings.Fields(segment)
	config := newDefaultConfig()
	
	for _, token := range tokens {
		if config.Heads[token] || l.pathHeadPattern.MatchString(token) {
			return strings.Index(segment, token)
		}
	}
	
	return -1
}

func (l *Lexer) NormalizeWhitespace(s string) string {
	return l.whitespacePattern.ReplaceAllString(strings.TrimSpace(s), " ")
}

func (l *Lexer) IsHead(token string) bool {
	config := newDefaultConfig()
	
	if config.Heads[token] {
		return true
	}
	
	if l.isExecutablePath(token) {
		return true
	}
	
	return false
}

func (l *Lexer) isExecutablePath(token string) bool {
	executablePaths := []string{
		"/bin/",
		"/sbin/", 
		"/usr/bin/",
		"/usr/sbin/",
		"/usr/local/bin/",
		"/opt/bin/",
	}
	
	for _, execPath := range executablePaths {
		if strings.Contains(token, execPath) {
			return true
		}
	}
	
	libraryPaths := []string{
		"/usr/lib/",
		"/System/Library/",
		"/Library/Frameworks/",
		".dylib",
		".framework",
		".bundle",
	}
	
	for _, libPath := range libraryPaths {
		if strings.Contains(token, libPath) {
			return false
		}
	}
	
	if strings.HasPrefix(token, "/usr/") || strings.HasPrefix(token, "/System/") {
		return false
	}
	
	if strings.HasPrefix(token, "/") && !strings.Contains(token, ".") {
		return true
	}
	
	return false
}

func (l *Lexer) TokenizeQuoted(s string) []string {
	if s == "" {
		return nil
	}
	
	if (strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`)) ||
	   (strings.HasPrefix(s, `'`) && strings.HasSuffix(s, `'`)) {
		return []string{s}
	}
	
	needsQuoting := regexp.MustCompile(`\s|[|;&><(){}]`)
	if needsQuoting.MatchString(s) {
		escaped := strings.ReplaceAll(s, `"`, `\"`)
		return []string{`"` + escaped + `"`}
	}
	
	return strings.Fields(s)
}

func (l *Lexer) IsNoiseToken(token string) bool {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`^(?:Usage:|usage:)`),
		regexp.MustCompile(`Copyright`),
		regexp.MustCompile(`^(?:NS[A-Z]\w+|objc\w+|NSError\w*|CF\w+|kCF\w+)$`),
		regexp.MustCompile(`^-(?:O[0-3s]?|g|Wall|W[\w-]+|f[a-z0-9-]+)$`),
		regexp.MustCompile(`^__[A-Z_]+$`), // __TEXT, __DATA, etc.
		regexp.MustCompile(`^_[a-z_]+$`),  // _main, _system, etc.
		regexp.MustCompile(`loader_\w+\.out$`),
		regexp.MustCompile(`[^\x20-\x7E]{3,}`), // Non-printable characters
	}
	
	for _, pattern := range patterns {
		if pattern.MatchString(token) {
			return true
		}
	}
	
	if l.HasTooMuchBinaryData(token) {
		return true
	}
	
	return false
}

func (l *Lexer) HasTooMuchBinaryData(s string) bool {
	if len(s) == 0 {
		return false
	}
	
	nonPrintable := 0
	for _, r := range s {
		if r < 0x20 || r > 0x7E {
			nonPrintable++
		}
	}
	
	return float64(nonPrintable)/float64(len(s)) > 0.2
}

func (l *Lexer) ContainsShellOperators(s string) bool {
	operators := []string{"|", "&&", ";", "$", "`", ">", "<"}
	
	for _, op := range operators {
		if strings.Contains(s, op) {
			return true
		}
	}
	
	return false
}

func (l *Lexer) HasControlChars(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return true
		}
	}
	return false
}