package jcs

import (
	"bufio"
	"compress/gzip"
	"encoding/binary"
	"encoding/hex"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The vectors under testdata/ are published by the author of RFC 8785 with
// the reference implementation, at
// https://github.com/cyberphone/json-canonicalization (commit 19d51d7,
// Apache License 2.0): input/ and output/ are its testdata directories, and
// es6-numbers.txt.gz is the first 5,000 lines of its es6testfile100m.txt.gz.
// They are the second implementation this canonicalizer is checked against.

func TestReferenceVectors(t *testing.T) {
	inputs, err := filepath.Glob("testdata/input/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 6 {
		t.Fatalf("found %d input vectors, want 6", len(inputs))
	}
	for _, in := range inputs {
		name := filepath.Base(in)
		t.Run(strings.TrimSuffix(name, ".json"), func(t *testing.T) {
			input, err := os.ReadFile(in)
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(filepath.Join("testdata/output", name))
			if err != nil {
				t.Fatal(err)
			}
			got, err := Canonicalize(input)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(want) {
				t.Errorf("got  %s\nwant %s", got, want)
			}
		})
	}
}

// TestES6Numbers feeds each IEEE-754 value in Go's own exponent notation and
// expects the ECMAScript serialization RFC 8785 §3.2.2.3 prescribes.
func TestES6Numbers(t *testing.T) {
	f, err := os.Open("testdata/es6-numbers.txt.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	lines := 0
	scanner := bufio.NewScanner(gz)
	for scanner.Scan() {
		hexBits, want, ok := strings.Cut(scanner.Text(), ",")
		if !ok {
			t.Fatalf("malformed line %q", scanner.Text())
		}
		lines++
		value := math.Float64frombits(parseBits(t, hexBits))
		input := strconv.FormatFloat(value, 'e', -1, 64)
		got, err := Canonicalize([]byte(input))
		if err != nil {
			t.Fatalf("%s (%s): %v", hexBits, input, err)
		}
		if string(got) != want {
			t.Errorf("%s: got %s, want %s", hexBits, got, want)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if lines != 5000 {
		t.Fatalf("read %d number vectors, want 5000", lines)
	}
}

func parseBits(t *testing.T, s string) uint64 {
	t.Helper()
	b, err := hex.DecodeString(strings.Repeat("0", 16-len(s)) + s)
	if err != nil {
		t.Fatal(err)
	}
	return binary.BigEndian.Uint64(b)
}

// TestRFC8785Example is the example of RFC 8785 §3.2.4.
func TestRFC8785Example(t *testing.T) {
	input := `{
  "numbers": [333333333.33333329, 1E30, 4.50,
              2e-3, 0.000000000000000000000000001],
  "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
  "literals": [null, true, false]
}`
	want := `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`
	got, err := Canonicalize([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestRefusesNonIJSON(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"duplicate_member", `{"a":1,"a":2}`},
		{"nested_duplicate_member", `{"x":{"a":1,"a":1}}`},
		{"unpaired_high_surrogate", `"\ud800"`},
		{"unpaired_low_surrogate", `"\udc00x"`},
		{"invalid_utf8", "\"\xff\""},
		{"trailing_garbage", `{} {}`},
		{"not_json", `{a:1}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := Canonicalize([]byte(tt.input)); err == nil {
				t.Fatalf("accepted %q as %q", tt.input, got)
			}
		})
	}
}

func TestDoesNotModifyInput(t *testing.T) {
	input := []byte(`{"b": 1, "a": 2}`)
	before := string(input)
	if _, err := Canonicalize(input); err != nil {
		t.Fatal(err)
	}
	if string(input) != before {
		t.Fatalf("input changed to %q", input)
	}
}

func TestSHA256Hex(t *testing.T) {
	// SHA-256 of the canonical text {"a":1,"b":2}, computed independently
	// with: printf '{"a":1,"b":2}' | sha256sum
	const want = "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"
	got, err := SHA256Hex([]byte(`{ "b": 2.0, "a": 1 }`))
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}
