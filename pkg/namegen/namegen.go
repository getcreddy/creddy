// Package namegen generates Docker-style human-readable identifiers.
// Format: adjective_surname (e.g., "brave_turing")
package namegen

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// adjectives is a list of positive/neutral adjectives
var adjectives = []string{
	"admiring", "agile", "amazing", "bold", "brave",
	"bright", "busy", "calm", "clever", "cool",
	"daring", "determined", "eager", "elegant", "epic",
	"fearless", "focused", "friendly", "gallant", "gentle",
	"gracious", "happy", "hardcore", "hopeful", "hungry",
	"inspiring", "jolly", "keen", "kind", "laughing",
	"loving", "lucid", "magical", "merry", "modest",
	"mystical", "nifty", "noble", "optimistic", "peaceful",
	"pedantic", "pensive", "quirky", "relaxed", "reverent",
	"romantic", "serene", "sharp", "silly", "sleepy",
	"stoic", "strange", "tender", "thirsty", "trusting",
	"upbeat", "vibrant", "vigilant", "wizardly", "wonderful",
	"youthful", "zealous", "zen",
}

// surnames is a list of famous scientists, engineers, hackers, and tech pioneers
var surnames = []string{
	"albattani", "allen", "almeida", "antonelli", "archimedes",
	"babbage", "banach", "banzai", "bardeen", "bartik",
	"bell", "benz", "berners_lee", "blackwell", "bohr",
	"booth", "borg", "bose", "boyd", "brahmagupta",
	"brattain", "brown", "carson", "cerf", "chandrasekhar",
	"chatelet", "clarke", "colden", "cori", "cray",
	"curie", "darwin", "davinci", "dijkstra", "draper",
	"dubinsky", "easley", "edison", "einstein", "elgamal",
	"elion", "engelbart", "euclid", "euler", "faraday",
	"feistel", "fermat", "fermi", "feynman", "franklin",
	"gagarin", "galileo", "gates", "gauss", "germain",
	"goldberg", "goldstine", "goldwasser", "golick", "goodall",
	"gosling", "greider", "hamilton", "haslett", "hawking",
	"heisenberg", "hellman", "herschel", "hodgkin", "hofstadter",
	"hoover", "hopper", "hugle", "hypatia", "jackson",
	"jang", "jennings", "jepsen", "jobs", "johnson",
	"kahn", "kapitsa", "kare", "keller", "kepler",
	"khorana", "kilby", "kirch", "knuth", "kowalevski",
	"lamport", "lamarr", "leakey", "leavitt", "leibniz",
	"lichterman", "liskov", "lovelace", "lumiere", "mahavira",
	"margulis", "matsumoto", "maxwell", "mccarthy", "mcclintock",
	"mclean", "mcnulty", "meitner", "mendel", "mendeleev",
	"merkle", "minsky", "mirzakhani", "montalcini", "moore",
	"morse", "murdock", "napier", "nash", "neumann",
	"newton", "nightingale", "nobel", "noether", "northcutt",
	"noyce", "panini", "pare", "pascal", "pasteur",
	"payne", "perlman", "pike", "poincare", "poitras",
	"ptolemy", "raman", "ramanujan", "ride", "ritchie",
	"rhodes", "robinson", "roentgen", "rosalind", "rubin",
	"saha", "sammet", "sanderson", "satoshi", "shamir",
	"shannon", "shaw", "shirley", "shockley", "sinoussi",
	"snyder", "solomon", "spence", "stallman", "stonebraker",
	"swanson", "swartz", "swirles", "taussig", "tereshkova",
	"tesla", "thompson", "torvalds", "turing", "varahamihira",
	"vaughan", "villani", "visvesvaraya", "volhard", "wescoff",
	"wilbur", "wiles", "williams", "wilson", "wing",
	"wozniak", "wright", "wu", "yonath", "zhukovsky",
}

// Generate creates a unique human-readable identifier.
// Format: adjective_surname_hex (e.g., "brave_turing_a7f")
// With 63 adjectives × 180 surnames × 4096 suffixes = ~46 million combinations
func Generate() string {
	adj := adjectives[randInt(len(adjectives))]
	sur := surnames[randInt(len(surnames))]
	return fmt.Sprintf("%s_%s", adj, sur)
}

// GenerateWithPrefix creates an identifier with a custom prefix.
// Format: prefix_adjective_surname_hex (e.g., "enr_brave_turing_a7f")
func GenerateWithPrefix(prefix string) string {
	if prefix == "" {
		return Generate()
	}
	return prefix + "_" + Generate()
}

// randInt returns a cryptographically random int in [0, max)
func randInt(max int) int {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		// Fallback shouldn't happen, but use 0 if it does
		return 0
	}
	return int(n.Int64())
}
