package cmdshark

import (
	"regexp"
	"strings"
)

type Parser struct {
	lexer             Lexer
	shellOpPattern    *regexp.Regexp
	redirectPattern   *regexp.Regexp
	urlPattern        *regexp.Regexp
	pathPattern       *regexp.Regexp
	assignPattern     *regexp.Regexp
	envRefPattern     *regexp.Regexp
}

type ParseResult struct {
	Tokens  []string
	Indices []int
	Methods []string
}

func NewParser() Parser {
	return Parser{
		lexer:           NewLexer(),
		shellOpPattern:  regexp.MustCompile(`^(\|\||\||&&|;|<<?|>>?|2>>?|&>)$`),
		redirectPattern: regexp.MustCompile(`^(?:\d?>&?\d?|\d?>>?|<<-?)$`),
		urlPattern:      regexp.MustCompile(`^(?:https?|ftp)://[\w\-._~:/?#@!$&'()*+,;=%]+$`),
		pathPattern:     regexp.MustCompile(`^(/|\./|\.\./|~\/)[^\s]*$`),
		assignPattern:   regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=.*`),
		envRefPattern:   regexp.MustCompile(`\$[{(]?[A-Za-z_][A-Za-z0-9_]*[)}]?`),
	}
}

func (p *Parser) FindSeedPositions(stream []string) []int {
	var seeds []int
	
	for i, token := range stream {
		if token == "" || p.lexer.IsNoiseToken(token) {
			continue
		}
		
		parts := strings.Fields(token)
		if len(parts) == 0 {
			continue
		}
		
		first := parts[0]
		
		if p.lexer.IsHead(first) || p.assignPattern.MatchString(first) {
			seeds = append(seeds, i)
			continue
		}
		
		if p.shellOpPattern.MatchString(token) || p.envRefPattern.MatchString(token) {
			seeds = append(seeds, i)
			continue
		}
		
		if p.lexer.ContainsShellOperators(token) {
			seeds = append(seeds, i)
		}
	}
	
	return seeds
}

func (p *Parser) ExpandFromPosition(stream []string, pos int, config Config) ParseResult {
	result := ParseResult{
		Tokens:  make([]string, 0),
		Indices: make([]int, 0),
		Methods: make([]string, 0),
	}
	
	i := pos
	var head string
	consumed := 0
	segmentFragments := 0
	
	for i < len(stream) && consumed < config.MaxWindow && len(result.Indices) < config.MaxFragmentsTotal {
		token := stream[i]
		
		if p.lexer.IsNoiseToken(token) {
			result.Methods = append(result.Methods, "stop:noise")
			break
		}
		
		parts := strings.Fields(token)
		if len(parts) == 0 {
			i++
			consumed++
			continue
		}
		
		if p.shellOpPattern.MatchString(token) {
			result.Tokens = append(result.Tokens, parts[0])
			result.Methods = append(result.Methods, "append:operator")
			result.Indices = append(result.Indices, i)
			i++
			consumed++
			segmentFragments = 0
			head = ""
			continue
		}
		
		if len(result.Tokens) == 0 {
			if p.assignPattern.MatchString(parts[0]) && len(parts) > 1 && p.lexer.IsHead(parts[1]) {
				result.Tokens = append(result.Tokens, parts[:2]...)
				head = parts[1]
				if len(parts) > 2 {
					result.Tokens = append(result.Tokens, parts[2:]...)
				}
				result.Methods = append(result.Methods, "seed:assign+head")
			} else if p.lexer.IsHead(parts[0]) {
				result.Tokens = append(result.Tokens, parts...)
				head = parts[0]
				result.Methods = append(result.Methods, "seed:plain")
			} else {
				result.Methods = append(result.Methods, "skip:nonhead_seed")
				break
			}
			
			result.Indices = append(result.Indices, i)
			i++
			consumed++
			segmentFragments = 1
			continue
		}
		
		if segmentFragments >= config.MaxFragmentsPerSegment {
			if i < len(stream) && p.shellOpPattern.MatchString(stream[i]) {
				continue
			}
			result.Methods = append(result.Methods, "stop:seg_frag_cap")
			break
		}
		
		if head != "" && len(result.Tokens) > 0 {
			arity := p.getOptionArity(head, result.Tokens[len(result.Tokens)-1], config)
			if arity == 1 {
				val := strings.Join(parts, " ")
				result.Tokens = append(result.Tokens, p.quoteIfNeeded(val))
				result.Methods = append(result.Methods, "bind:option→value")
				result.Indices = append(result.Indices, i)
				i++
				consumed++
				segmentFragments++
				continue
			}
		}
		
		if p.redirectPattern.MatchString(parts[0]) {
			result.Tokens = append(result.Tokens, parts...)
			result.Methods = append(result.Methods, "append:redirect")
			result.Indices = append(result.Indices, i)
			i++
			consumed++
			segmentFragments++
			continue
		}
		
		if p.urlPattern.MatchString(token) || p.pathPattern.MatchString(token) {
			result.Tokens = append(result.Tokens, token)
			result.Methods = append(result.Methods, "append:url_or_path")
			result.Indices = append(result.Indices, i)
			i++
			consumed++
			segmentFragments++
			continue
		}
		
		if len(result.Tokens) > 0 {
			prev := result.Tokens[len(result.Tokens)-1]
			if strings.HasPrefix(prev, "-") && len(prev) <= 4 && !strings.HasPrefix(prev, "--") {
				result.Tokens = append(result.Tokens, p.quoteIfNeeded(strings.Join(parts, " ")))
				result.Methods = append(result.Methods, "bind:shortopt")
				result.Indices = append(result.Indices, i)
				i++
				consumed++
				segmentFragments++
				continue
			}
		}
		
		anyOpPattern := regexp.MustCompile(`(\|\||\||&&|;|<<?|>>?|2>>?|&>)`)
		if len(parts) > 1 && !anyOpPattern.MatchString(token) {
			result.Tokens = append(result.Tokens, p.quoteIfNeeded(strings.Join(parts, " ")))
			result.Methods = append(result.Methods, "append:multiword_arg")
			result.Indices = append(result.Indices, i)
			i++
			consumed++
			segmentFragments++
			continue
		}
		
		result.Tokens = append(result.Tokens, parts...)
		result.Methods = append(result.Methods, "append:plain")
		result.Indices = append(result.Indices, i)
		i++
		consumed++
		segmentFragments++
	}
	
	return result
}

func (p *Parser) getOptionArity(head, option string, config Config) int {
	if headOptions, exists := config.OptionArity[head]; exists {
		if arity, exists := headOptions[option]; exists {
			return arity
		}
	}
	return 0
}

func (p *Parser) quoteIfNeeded(s string) string {
	if s == "" {
		return s
	}
	
	if (strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`)) ||
	   (strings.HasPrefix(s, `'`) && strings.HasSuffix(s, `'`)) {
		return s
	}
	
	needsQuoting := regexp.MustCompile(`\s|[|;&><(){}]`)
	if needsQuoting.MatchString(s) {
		escaped := strings.ReplaceAll(s, `"`, `\"`)
		return `"` + escaped + `"`
	}
	
	return s
}