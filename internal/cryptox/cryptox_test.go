package cryptox

import (
	"bytes"
	"testing"
)

func TestSealOpen(t *testing.T) {
	key, err := NewSalt(32)
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("secret-payload")
	blob, err := Seal(key, plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(key, blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("got %q", got)
	}
}

func TestOpenRejectsTamper(t *testing.T) {
	key, _ := NewSalt(32)
	blob, _ := Seal(key, []byte("x"))
	blob[len(blob)-1] ^= 0xff
	if _, err := Open(key, blob); err != ErrInvalidCiphertext {
		t.Fatalf("err=%v", err)
	}
}

func TestDeriveKEKDeterministic(t *testing.T) {
	salt := bytes.Repeat([]byte{1}, 16)
	a := DeriveKEK("passw0rd", salt)
	b := DeriveKEK("passw0rd", salt)
	if !bytes.Equal(a, b) || len(a) != 32 {
		t.Fatal("kek mismatch")
	}
	c := DeriveKEK("other", salt)
	if bytes.Equal(a, c) {
		t.Fatal("different passwords must differ")
	}
}

func TestSealBadKey(t *testing.T) {
	if _, err := Seal([]byte("short"), []byte("x")); err == nil {
		t.Fatal("expected error")
	}
}
