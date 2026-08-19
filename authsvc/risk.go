package main

import (
	"time"
	"math"
)

const (
	scoreNewDevice        = 30
	scoreNewCountry       = 25
	scoreImpossibleTravel = 50
	scoreUserVelocity     = 25
	scoreIPVelocity       = 25
	scoreUnknownGeo       = 10
)

const (
	thresholdChallenge = 40
	thresholdBlock     = 70
)

const (
	impossibleTravelKmH  = 900 // faster than commercial air travel
	velocityWindow       = 15 * time.Minute
	userFailureThreshold = 3
	ipFailureThreshold   = 8
	challengeTTL         = 5 * time.Minute
	maxChallengeAttempts = 5
)

func haversineKm(lat1, lon1, lat2, lon2 float64) float64 {
	const earthRadiusKm = 6371.0

	lat1Rad := lat1 * math.Pi / 180
	lat2Rad := lat2 * math.Pi / 180
	deltaLat := (lat2 - lat1) * math.Pi / 180
	deltaLon := (lon2 - lon1) * math.Pi / 180

	a := math.Sin(deltaLat/2)*math.Sin(deltaLat/2) +
		math.Cos(lat1Rad)*math.Cos(lat2Rad)*
			math.Sin(deltaLon/2)*math.Sin(deltaLon/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))

	return earthRadiusKm * c
}