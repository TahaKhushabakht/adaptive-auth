package main

import (
	"time"
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
