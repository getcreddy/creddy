package policy

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Policy defines auto-approval rules for agent enrollment
type Policy struct {
	Name   string      `yaml:"name" json:"name"`
	Match  MatchRules  `yaml:"match" json:"match"`
	Allow  *AllowRules `yaml:"allow,omitempty" json:"allow,omitempty"`
	Deny   *DenyRules  `yaml:"deny,omitempty" json:"deny,omitempty"`
	Limits *Limits     `yaml:"limits,omitempty" json:"limits,omitempty"`
}

type MatchRules struct {
	NamePattern string `yaml:"name_pattern" json:"name_pattern"`
}

type AllowRules struct {
	Scopes           []string `yaml:"scopes" json:"scopes"`
	MaxTTL           Duration `yaml:"max_ttl" json:"max_ttl"`
	MaxAgentLifetime Duration `yaml:"max_agent_lifetime" json:"max_agent_lifetime"`
}

type DenyRules struct {
	Scopes []string `yaml:"scopes" json:"scopes"`
}

type Limits struct {
	MaxAgents int    `yaml:"max_agents" json:"max_agents"`
	Rate      string `yaml:"rate" json:"rate"` // e.g., "10/hour"
}

// Duration wraps time.Duration for YAML parsing
type Duration time.Duration

func (d *Duration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(dur)
	return nil
}

func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

// Engine evaluates policies
type Engine struct {
	policies []Policy
	mu       sync.RWMutex

	// Rate limiting state
	rateCounts map[string]*rateCounter
	ratesMu    sync.Mutex
}

type rateCounter struct {
	count     int
	window    time.Time
	windowDur time.Duration
}

func NewEngine(policies []Policy) *Engine {
	return &Engine{
		policies:   policies,
		rateCounts: make(map[string]*rateCounter),
	}
}

func (e *Engine) SetPolicies(policies []Policy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policies = policies
}

// EvaluationResult contains the result of policy evaluation
type EvaluationResult struct {
	AutoApprove      bool
	PolicyName       string
	MaxTTL           time.Duration
	MaxAgentLifetime time.Duration
	DenyReason       string
}

// Evaluate checks if an enrollment should be auto-approved
func (e *Engine) Evaluate(agentName string, requestedScopes []string) EvaluationResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, policy := range e.policies {
		// Check name pattern match
		if !matchPattern(policy.Match.NamePattern, agentName) {
			continue
		}

		// Found matching policy

		// If no allow rules, this policy requires manual approval
		if policy.Allow == nil {
			return EvaluationResult{
				AutoApprove: false,
				PolicyName:  policy.Name,
				DenyReason:  "policy requires manual approval",
			}
		}

		// Check deny list first
		if policy.Deny != nil {
			for _, scope := range requestedScopes {
				if matchAnyScope(policy.Deny.Scopes, scope) {
					return EvaluationResult{
						AutoApprove: false,
						PolicyName:  policy.Name,
						DenyReason:  "scope denied by policy: " + scope,
					}
				}
			}
		}

		// Check all requested scopes are in allow list
		for _, scope := range requestedScopes {
			if !matchAnyScope(policy.Allow.Scopes, scope) {
				return EvaluationResult{
					AutoApprove: false,
					PolicyName:  policy.Name,
					DenyReason:  "scope not in allow list: " + scope,
				}
			}
		}

		// Check rate limits
		if policy.Limits != nil {
			if !e.checkRateLimit(policy.Name, policy.Limits) {
				return EvaluationResult{
					AutoApprove: false,
					PolicyName:  policy.Name,
					DenyReason:  "rate limit exceeded",
				}
			}
		}

		// All checks passed
		return EvaluationResult{
			AutoApprove:      true,
			PolicyName:       policy.Name,
			MaxTTL:           policy.Allow.MaxTTL.Duration(),
			MaxAgentLifetime: policy.Allow.MaxAgentLifetime.Duration(),
		}
	}

	// No matching policy
	return EvaluationResult{
		AutoApprove: false,
		DenyReason:  "no matching policy",
	}
}

// matchPattern matches a glob pattern against a name
func matchPattern(pattern, name string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	matched, _ := filepath.Match(pattern, name)
	return matched
}

// matchAnyScope checks if a scope matches any pattern in the list
func matchAnyScope(patterns []string, scope string) bool {
	for _, pattern := range patterns {
		if matchScope(pattern, scope) {
			return true
		}
	}
	return false
}

// matchScope checks if a scope matches a pattern
// Pattern "github:org/*" matches "github:org/repo", "github:org/repo:read", etc.
// Pattern "github:*:write" matches "github:anything:write" but not "github:anything:read"
func matchScope(pattern, scope string) bool {
	// Exact match
	if pattern == scope {
		return true
	}

	patternParts := strings.Split(pattern, ":")
	scopeParts := strings.Split(scope, ":")

	// If pattern ends with *, it matches anything after
	if len(patternParts) > 0 && patternParts[len(patternParts)-1] == "*" {
		// Pattern like "github:*" or "github:org/*"
		// Check prefix parts match
		for i := 0; i < len(patternParts)-1; i++ {
			if i >= len(scopeParts) {
				return false
			}
			if !matchPart(patternParts[i], scopeParts[i]) {
				return false
			}
		}
		return true
	}

	// Pattern has same or more parts - check each
	if len(patternParts) > len(scopeParts) {
		return false
	}

	for i, pp := range patternParts {
		if i >= len(scopeParts) {
			return false
		}
		if !matchPart(pp, scopeParts[i]) {
			return false
		}
	}

	// Pattern matched all its parts, scope may have more (that's ok for allow)
	return true
}

// matchPart matches a single part with possible glob
func matchPart(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	if strings.Contains(pattern, "*") || strings.Contains(pattern, "?") {
		matched, _ := filepath.Match(pattern, value)
		return matched
	}
	return pattern == value
}

// checkRateLimit checks and updates rate limit for a policy
func (e *Engine) checkRateLimit(policyName string, limits *Limits) bool {
	if limits.Rate == "" {
		return true
	}

	// Parse rate (e.g., "10/hour")
	parts := strings.Split(limits.Rate, "/")
	if len(parts) != 2 {
		return true
	}

	var count int
	fmt.Sscanf(parts[0], "%d", &count)

	var window time.Duration
	switch parts[1] {
	case "second":
		window = time.Second
	case "minute":
		window = time.Minute
	case "hour":
		window = time.Hour
	case "day":
		window = 24 * time.Hour
	default:
		return true
	}

	e.ratesMu.Lock()
	defer e.ratesMu.Unlock()

	rc, ok := e.rateCounts[policyName]
	if !ok || time.Since(rc.window) > rc.windowDur {
		// New window
		e.rateCounts[policyName] = &rateCounter{
			count:     1,
			window:    time.Now(),
			windowDur: window,
		}
		return true
	}

	if rc.count >= count {
		return false
	}

	rc.count++
	return true
}
