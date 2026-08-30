package version

import "testing"

func TestCurrentAndString(t *testing.T) {
	Version = "1.2.3"
	BuildDate = "2026-08-25T00:00:00Z"
	if String() != "1.2.3 (2026-08-25T00:00:00Z)" {
		t.Fatal(String())
	}
	info := Current()
	if info.Version != "1.2.3" || info.OS == "" {
		t.Fatalf("%+v", info)
	}
}
