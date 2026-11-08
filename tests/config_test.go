package tests

import (
	"testing"

	"ks-intercom-gateway/src/gateway"
)

// Bridges are kept by name, case and umlauts aside, whatever order the UI
// sends them in.
func TestBridgesAreSortedByName(t *testing.T) {
	store, err := gateway.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := store.Update(gateway.Config{Bridges: []gateway.Bridge{
		{Name: "Zimmer"}, {Name: "büro"}, {Name: "Ärztezimmer"}, {Name: "Bad"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, b := range cfg.Bridges {
		got = append(got, b.Name)
	}
	want := []string{"Ärztezimmer", "Bad", "büro", "Zimmer"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order %v, want %v", got, want)
		}
	}
}

// So are the kiosks of a bridge: one added from the mDNS list lands at the
// end and takes its place on save.
func TestKiosksAreSortedByName(t *testing.T) {
	store, err := gateway.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := store.Update(gateway.Config{Bridges: []gateway.Bridge{{Name: "Haus", Kiosks: []gateway.Kiosk{
		{Name: "Wohnzimmer", Host: "10.0.0.3"}, {Name: "Flur", Host: "10.0.0.1"}, {Name: "Echo Dot 2", Host: "10.0.0.9"}, {Name: "Ärztezimmer", Host: "10.0.0.4"},
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, k := range cfg.Bridges[0].Kiosks {
		got = append(got, k.Name)
	}
	want := []string{"Ärztezimmer", "Echo Dot 2", "Flur", "Wohnzimmer"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order %v, want %v", got, want)
		}
	}
}
