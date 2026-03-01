package policy

import (
	"testing"
	"time"
)

func TestMatchScope(t *testing.T) {
	tests := []struct {
		pattern string
		scope   string
		want    bool
	}{
		// Exact matches
		{"github", "github", true},
		{"anthropic", "anthropic", true},
		{"github:org/repo", "github:org/repo", true},

		// Wildcard at end
		{"github:*", "github:org/repo", true},
		{"github:*", "github:anything", true},
		{"github:org/*", "github:org/repo", true},
		{"github:org/*", "github:org/repo:read", true},

		// Glob patterns
		{"github:myorg/*", "github:myorg/app", true},
		{"github:myorg/*", "github:otherorg/app", false},

		// Non-matches
		{"github", "anthropic", false},
		{"github:org/repo", "github:org/other", false},
		{"github:org/*", "github:other/repo", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.scope, func(t *testing.T) {
			got := matchScope(tt.pattern, tt.scope)
			if got != tt.want {
				t.Errorf("matchScope(%q, %q) = %v, want %v", tt.pattern, tt.scope, got, tt.want)
			}
		})
	}
}

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"*", "anything", true},
		{"", "anything", true},
		{"ci-*", "ci-build-123", true},
		{"ci-*", "prod-app", false},
		{"worker-?", "worker-1", true},
		{"worker-?", "worker-12", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.name, func(t *testing.T) {
			got := matchPattern(tt.pattern, tt.name)
			if got != tt.want {
				t.Errorf("matchPattern(%q, %q) = %v, want %v", tt.pattern, tt.name, got, tt.want)
			}
		})
	}
}

func TestEvaluate_AutoApprove(t *testing.T) {
	policies := []Policy{
		{
			Name: "ci-agents",
			Match: MatchRules{
				NamePattern: "ci-*",
			},
			Allow: &AllowRules{
				Scopes:           []string{"github:myorg/*", "anthropic"},
				MaxTTL:           Duration(time.Hour),
				MaxAgentLifetime: Duration(24 * time.Hour),
			},
		},
	}

	engine := NewEngine(policies)

	// Should auto-approve
	result := engine.Evaluate("ci-build-123", []string{"github:myorg/app", "anthropic"})
	if !result.AutoApprove {
		t.Errorf("expected auto-approve, got deny: %s", result.DenyReason)
	}
	if result.PolicyName != "ci-agents" {
		t.Errorf("expected policy 'ci-agents', got %q", result.PolicyName)
	}
}

func TestEvaluate_DenyUnknownScope(t *testing.T) {
	policies := []Policy{
		{
			Name: "ci-agents",
			Match: MatchRules{
				NamePattern: "ci-*",
			},
			Allow: &AllowRules{
				Scopes: []string{"github:myorg/*"},
			},
		},
	}

	engine := NewEngine(policies)

	// Should deny - aws not in allow list
	result := engine.Evaluate("ci-build-123", []string{"github:myorg/app", "aws"})
	if result.AutoApprove {
		t.Error("expected deny for unknown scope")
	}
	if result.DenyReason == "" {
		t.Error("expected deny reason")
	}
}

func TestEvaluate_ExplicitDeny(t *testing.T) {
	policies := []Policy{
		{
			Name: "ci-agents",
			Match: MatchRules{
				NamePattern: "ci-*",
			},
			Allow: &AllowRules{
				Scopes: []string{"github:*"},
			},
			Deny: &DenyRules{
				Scopes: []string{"github:*:write"},
			},
		},
	}

	engine := NewEngine(policies)

	// Should allow read
	result := engine.Evaluate("ci-build-123", []string{"github:myorg/app:read"})
	if !result.AutoApprove {
		t.Errorf("expected auto-approve for read, got: %s", result.DenyReason)
	}

	// Should deny write
	result = engine.Evaluate("ci-build-123", []string{"github:myorg/app:write"})
	if result.AutoApprove {
		t.Error("expected deny for write scope")
	}
}

func TestEvaluate_NoMatchingPolicy(t *testing.T) {
	policies := []Policy{
		{
			Name: "ci-agents",
			Match: MatchRules{
				NamePattern: "ci-*",
			},
			Allow: &AllowRules{
				Scopes: []string{"github:*"},
			},
		},
	}

	engine := NewEngine(policies)

	// Should not match - name doesn't match pattern
	result := engine.Evaluate("prod-app", []string{"github:myorg/app"})
	if result.AutoApprove {
		t.Error("expected no match for prod-app")
	}
}

func TestEvaluate_ManualApprovalPolicy(t *testing.T) {
	policies := []Policy{
		{
			Name: "default",
			Match: MatchRules{
				NamePattern: "*",
			},
			// No Allow = manual approval
		},
	}

	engine := NewEngine(policies)

	result := engine.Evaluate("any-agent", []string{"github:myorg/app"})
	if result.AutoApprove {
		t.Error("expected manual approval required")
	}
	if result.PolicyName != "default" {
		t.Errorf("expected policy 'default', got %q", result.PolicyName)
	}
}

func TestEvaluate_FirstMatchWins(t *testing.T) {
	policies := []Policy{
		{
			Name: "ci-agents",
			Match: MatchRules{
				NamePattern: "ci-*",
			},
			Allow: &AllowRules{
				Scopes: []string{"github:*"},
			},
		},
		{
			Name: "default",
			Match: MatchRules{
				NamePattern: "*",
			},
			// Manual approval
		},
	}

	engine := NewEngine(policies)

	// ci-* should match first policy
	result := engine.Evaluate("ci-build", []string{"github:app"})
	if !result.AutoApprove {
		t.Errorf("expected auto-approve for ci-*, got: %s", result.DenyReason)
	}

	// other should match default (manual)
	result = engine.Evaluate("prod-app", []string{"github:app"})
	if result.AutoApprove {
		t.Error("expected manual for prod-app")
	}
}
