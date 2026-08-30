package sqlite_test

import (
	"path/filepath"
	"testing"

	"gokeeper/internal/storage/sqlite"
)

func TestOpenCreatesSchema(t *testing.T) {
	db, err := sqlite.Open(filepath.Join(t.TempDir(), "a", "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer sqlite.Close(db)
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='items'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("items table missing")
	}
}
