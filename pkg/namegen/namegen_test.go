package namegen

import (
	"regexp"
	"testing"
)

func TestGenerate(t *testing.T) {
	// Test format: adjective_surname (surname may contain underscores, e.g., berners_lee)
	pattern := regexp.MustCompile(`^[a-z]+_[a-z_]+$`)
	
	for i := 0; i < 100; i++ {
		id := Generate()
		if !pattern.MatchString(id) {
			t.Errorf("Generate() = %q, doesn't match expected pattern", id)
		}
	}
}

func TestGenerateWithPrefix(t *testing.T) {
	// Test format: prefix_adjective_surname (surname may contain underscores)
	pattern := regexp.MustCompile(`^cli_[a-z]+_[a-z_]+$`)
	
	id := GenerateWithPrefix("cli")
	if !pattern.MatchString(id) {
		t.Errorf("GenerateWithPrefix(\"cli\") = %q, doesn't match expected pattern", id)
	}
	
	// Empty prefix should just return Generate() format
	id2 := GenerateWithPrefix("")
	pattern2 := regexp.MustCompile(`^[a-z]+_[a-z_]+$`)
	if !pattern2.MatchString(id2) {
		t.Errorf("GenerateWithPrefix(\"\") = %q, doesn't match expected pattern", id2)
	}
}

func TestRandomness(t *testing.T) {
	// Generate many IDs and verify we get variety
	const count = 100
	seen := make(map[string]bool, count)
	
	for i := 0; i < count; i++ {
		id := Generate()
		seen[id] = true
	}
	
	// With ~11k combinations (63 adj * 180 surnames), 100 samples should mostly be unique
	if len(seen) < 90 {
		t.Errorf("Expected mostly unique IDs in small sample, got %d unique out of %d", len(seen), count)
	}
}
