package main

import (
	"testing"

	"github.com/veil-protocol/veil-core/morph"
)

func TestScoreSizeDistribution(t *testing.T) {
	tests := []struct {
		name    string
		profile *morph.Profile
		minScore float64
	}{
		{
			name:     "http2_browsing has good spread",
			profile:  morph.BuiltinHTTP2Profile(),
			minScore: 75,
		},
		{
			name:     "chrome_real has many buckets",
			profile:  morph.BuiltinChromeRealProfile(),
			minScore: 80,
		},
		{
			name: "single bucket is bad",
			profile: &morph.Profile{
				PacketSizes: morph.SizeDistribution{
					Buckets: []morph.SizeBucket{
						{Min: 1400, Max: 1460, Weight: 100},
					},
				},
			},
			minScore: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := scoreSizeDistribution(tt.profile)
			if score < tt.minScore {
				t.Errorf("score %.1f < min %.1f", score, tt.minScore)
			}
			t.Logf("score: %.1f", score)
		})
	}
}

func TestScoreTimingRealism(t *testing.T) {
	tests := []struct {
		name     string
		profile  *morph.Profile
		minScore float64
	}{
		{
			name:     "http2 has good timing",
			profile:  morph.BuiltinHTTP2Profile(),
			minScore: 80,
		},
		{
			name: "zero jitter is bad",
			profile: &morph.Profile{
				Timing: morph.TimingProfile{
					MinDelayMs: 0, MaxDelayMs: 0,
					MeanDelayMs: 0, JitterMs: 0,
					BurstSize: 1, BurstGapMs: 0,
				},
			},
			minScore: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := scoreTimingRealism(tt.profile)
			if score < tt.minScore {
				t.Errorf("score %.1f < min %.1f", score, tt.minScore)
			}
			t.Logf("score: %.1f", score)
		})
	}
}

func TestScoreBurstPattern(t *testing.T) {
	tests := []struct {
		name     string
		profile  *morph.Profile
		minScore float64
	}{
		{
			name:     "discord has realistic burst",
			profile:  morph.BuiltinDiscordProfile(),
			minScore: 70,
		},
		{
			name: "burst size 1 is poor",
			profile: &morph.Profile{
				Timing: morph.TimingProfile{BurstSize: 1, BurstGapMs: 10},
			},
			minScore: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := scoreBurstPattern(tt.profile)
			if score < tt.minScore {
				t.Errorf("score %.1f < min %.1f", score, tt.minScore)
			}
			t.Logf("score: %.1f", score)
		})
	}
}

func TestGenerateRecommendations(t *testing.T) {
	// Good profile should have no recommendations.
	p := morph.BuiltinHTTP2Profile()
	recs := generateRecommendations(p, 90, 90, 90)
	if len(recs) != 0 {
		t.Errorf("expected 0 recommendations for good profile, got %d: %v", len(recs), recs)
	}

	// Bad profile should trigger recommendations.
	bad := &morph.Profile{
		PacketSizes: morph.SizeDistribution{
			Buckets: []morph.SizeBucket{
				{Min: 1400, Max: 1460, Weight: 95},
				{Min: 1460, Max: 2000, Weight: 5},
			},
		},
		Timing: morph.TimingProfile{
			MinDelayMs: 0, MaxDelayMs: 5,
			MeanDelayMs: 0, JitterMs: 1,
			BurstSize: 60, BurstGapMs: 2,
		},
	}
	recs = generateRecommendations(bad, 30, 30, 30)
	if len(recs) < 3 {
		t.Errorf("expected 3+ recommendations for bad profile, got %d", len(recs))
	}
	t.Logf("recommendations: %v", recs)
}

func TestAllBuiltinProfilesScoreWell(t *testing.T) {
	for _, pi := range morph.ListBuiltinProfiles() {
		t.Run(pi.Name, func(t *testing.T) {
			p := morph.GetBuiltinProfile(pi.Name)
			if p == nil {
				t.Fatal("nil profile")
			}

			sizeScore := scoreSizeDistribution(p)
			timingScore := scoreTimingRealism(p)
			burstScore := scoreBurstPattern(p)
			overall := (sizeScore*30 + timingScore*25 + 99.0*25 + burstScore*20) / 100

			if overall < 70 {
				t.Errorf("overall score %.1f < 70 for builtin profile", overall)
			}
			t.Logf("size=%.0f timing=%.0f burst=%.0f overall=%.0f", sizeScore, timingScore, burstScore, overall)
		})
	}
}
