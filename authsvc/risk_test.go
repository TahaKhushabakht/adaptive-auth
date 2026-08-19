package main

import(
	"testing"
)

func TestHaversineKm(t *testing.T) {
	tests := []struct {
		name                   string
		lat1, lon1, lat2, lon2 float64
		wantKm                 float64
		tolerance              float64
	}{
		{"same point", 40.7128, -74.0060, 40.7128, -74.0060, 0, 0.01},
		{"NYC to London", 40.7128, -74.0060, 51.5074, -0.1278, 5570, 20},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := haversineKm(tt.lat1, tt.lon1, tt.lat2, tt.lon2)
			diff := got - tt.wantKm
			if diff < 0 {
				diff = -diff
			}
			if diff > tt.tolerance {
				t.Errorf("haversineKm(%v,%v, %v,%v) = %v, want %v ± %v",
					tt.lat1, tt.lon1, tt.lat2, tt.lon2, got, tt.wantKm, tt.tolerance)
			}
		})
	}
}