package main

import "testing"

func TestUnicodeOffsets(t *testing.T) {
	s := "Привет, alice@example.com"
	byteStart := len("Привет, ")
	byteEnd := byteStart + len("alice@example.com")
	if got := byteToRuneOffset(s, byteStart); got != 8 {
		t.Fatalf("start offset: got %d want 8", got)
	}
	if got := byteToRuneOffset(s, byteEnd); got != 25 {
		t.Fatalf("end offset: got %d want 25", got)
	}
	if got := runeToByteOffset(s, 8); got != byteStart {
		t.Fatalf("roundtrip byte offset: got %d want %d", got, byteStart)
	}
}

func TestApplyOperator(t *testing.T) {
	got, op, err := applyOperator("alice@example.com", "EMAIL_ADDRESS", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "<EMAIL_ADDRESS>" || op != "replace" {
		t.Fatalf("got %q/%q", got, op)
	}

	got, op, err = applyOperator("secret", "TOKEN", map[string]operatorConfig{
		"TOKEN": {Type: "redact"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != "" || op != "redact" {
		t.Fatalf("got %q/%q", got, op)
	}
}
