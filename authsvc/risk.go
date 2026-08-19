package main

import (
	"database/sql"
	"math"
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

type riskContext struct {
	knownDevice   bool
	knownCountry  bool
	hasGeoHistory bool
	hasPriorLogin bool
	lastLat       float64
	lastLon       float64
	lastLoginAt   time.Time
	userFailures  int
	ipFailures    int
}

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

const sqliteTimeLayout = "2006-01-02 15:04:05"

func (s *apiServer) buildRiskContext(userID, deviceID, country, ip string) (riskContext, error) {
	var ctx riskContext

	rows, err := s.db.Query("SELECT device_id, country, latitude, longitude, created_at FROM login_events "+
		"WHERE user_id = ? AND event_type = 'login' AND success = 1 ORDER BY created_at DESC",
		userID,
	)
	if err != nil {
		return ctx, err
	}
	defer rows.Close()

	seenDevices := make(map[string]bool)
	seenCountries := make(map[string]bool)

	for rows.Next() {
		var rowDeviceID, rowCreatedAtStr string
		var rowCountry sql.NullString
		var rowLat, rowLon sql.NullFloat64

		if err := rows.Scan(&rowDeviceID, &rowCountry, &rowLat, &rowLon, &rowCreatedAtStr); err != nil {
			return ctx, err
		}
		seenDevices[rowDeviceID] = true
		if rowCountry.Valid {
			seenCountries[rowCountry.String] = true
			ctx.hasGeoHistory = true
		}

		if !ctx.hasPriorLogin {
			ctx.hasPriorLogin = true
			if rowLat.Valid && rowLon.Valid {
				ctx.lastLat = rowLat.Float64
				ctx.lastLon = rowLon.Float64
				if t, err := time.Parse(sqliteTimeLayout, rowCreatedAtStr); err == nil {
					ctx.lastLoginAt = t
				}
			}
		}
	}
	if err := rows.Err(); err != nil {
		return ctx, err
	}
	ctx.knownDevice = seenDevices[deviceID]
	ctx.knownCountry = seenCountries[country]

	cutoff := time.Now().UTC().Add(-velocityWindow).Format(sqliteTimeLayout)

	if err := s.db.QueryRow(
		"SELECT COUNT(*) FROM login_events WHERE user_id = ? AND event_type = 'login' AND success = 0 AND created_at > ?",
		userID, cutoff,
	).Scan(&ctx.userFailures); err != nil {
		return ctx, err
	}

	if err := s.db.QueryRow(
		"SELECT COUNT(*) FROM login_events WHERE ip_address = ? AND event_type = 'login' AND success = 0 AND created_at > ?",
		ip, cutoff,
	).Scan(&ctx.ipFailures); err != nil {
		return ctx, err
	}

	return ctx, nil
}
