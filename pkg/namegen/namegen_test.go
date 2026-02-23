package namegen

import (
	"regexp"
	"testing"
)

func TestGenerate(t *testing.T) {
	// Test format: adjective_surname_hex
	pattern := regexp.MustCompile(`^[a-z]+_[a-z_]+_[a-f0-9]{3}$`)
	
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		id := Generate()
		if !pattern.MatchString(id) {
			t.Errorf("Generate() = %q, doesn't match expected pattern", id)
		}
		seen[id] = true
	}
	
	// With 1000 samples, we should have high uniqueness
	// Allow some collisions but not many
	if len(seen) < 990 {
		t.Errorf("Expected mostly unique IDs, got %d unique out of 1000", len(seen))
	}
}

func TestGenerateWithPrefix(t *testing.T) {
	// Test format: prefix_adjective_surname_hex
	pattern := regexp.MustCompile(`^cli_[a-z]+_[a-z_]+_[a-f0-9]{3}$`)
	
	id := GenerateWithPrefix("cli")
	if !pattern.MatchString(id) {
		t.Errorf("GenerateWithPrefix(\"cli\") = %q, doesn't match expected pattern", id)
	}
	
	// Empty prefix should just return Generate() format
	id2 := GenerateWithPrefix("")
	pattern2 := regexp.MustCompile(`^[a-z]+_[a-z_]+_[a-f0-9]{3}$`)
	if !pattern2.MatchString(id2) {
		t.Errorf("GenerateWithPrefix(\"\") = %q, doesn't match expected pattern", id2)
	}
}

func TestUniqueness(t *testing.T) {
	// Generate many IDs and verify uniqueness
	const count = 10000
	seen := make(map[string]bool, count)
	
	for i := 0; i < count; i++ {
		id := Generate()
		if seen[id] {
			t.Logf("Collision at iteration %d: %s", i, id)
		}
		seen[id] = true
	}
	
	// With ~46M combinations, 10k samples should have near-zero collisions
	uniqueRatio := float64(len(seen)) / float64(count)
	if uniqueRatio < 0.999 {
		t.Errorf("Uniqueness ratio too low: %.4f (got %d unique out of %d)", uniqueRatio, len(seen), count)
	}
}
