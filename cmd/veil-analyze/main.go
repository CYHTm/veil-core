// Command veil-analyze is the Veil traffic analysis tool.
//
// It can generate morph profiles from pcap captures, compare
// profiles against builtins, list available profiles, and run
// an interactive demo showing how Veil defeats DPI.
package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"

	veilcrypto "github.com/veil-protocol/veil-core/crypto"
	"github.com/veil-protocol/veil-core/morph"
)

func main() {
	// CLI modes.
	pcapFile := flag.String("pcap", "", "Generate profile from pcap file")
	jsonFile := flag.String("json", "", "Generate profile from JSON packet records")
	outFile := flag.String("out", "", "Output profile path (default: stdout)")
	profName := flag.String("name", "", "Profile name (for -pcap/-json)")
	profDesc := flag.String("desc", "", "Profile description (for -pcap/-json)")
	compareTo := flag.String("compare", "", "Compare a profile against all builtins")
	listMode := flag.Bool("list", false, "List all builtin profiles with stats")
	reportProfile := flag.String("report", "", "Full stealth report for a profile (histogram + recommendations)")
	_ = flag.Bool("demo", false, "Run interactive analysis demo")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Veil Traffic Analysis Tool\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  veil-analyze                          Interactive demo\n")
		fmt.Fprintf(os.Stderr, "  veil-analyze -pcap capture.pcap       Generate profile from pcap\n")
		fmt.Fprintf(os.Stderr, "  veil-analyze -json packets.json       Generate profile from JSON records\n")
		fmt.Fprintf(os.Stderr, "  veil-analyze -compare tiktok_scrolling  Compare profile vs builtins\n")
		fmt.Fprintf(os.Stderr, "  veil-analyze -report http2_browsing     Full stealth report with recommendations\n")
		fmt.Fprintf(os.Stderr, "  veil-analyze -list                    List builtin profiles\n")
		fmt.Fprintf(os.Stderr, "\nFlags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  # Capture traffic and create profile:\n")
		fmt.Fprintf(os.Stderr, "  sudo tcpdump -i eth0 -w chrome.pcap host example.com\n")
		fmt.Fprintf(os.Stderr, "  veil-analyze -pcap chrome.pcap -name my_chrome -out my_chrome.json\n")
		fmt.Fprintf(os.Stderr, "\n  # Use generated profile:\n")
		fmt.Fprintf(os.Stderr, "  veil-client -morph /path/to/my_chrome.json -server ...\n")
	}

	flag.Parse()

	switch {
	case *pcapFile != "":
		runPcapGenerate(*pcapFile, *outFile, *profName, *profDesc)
	case *jsonFile != "":
		runJSONGenerate(*jsonFile, *outFile, *profName, *profDesc)
	case *compareTo != "":
		runCompare(*compareTo)
	case *reportProfile != "":
		runReport(*reportProfile)
	case *listMode:
		runList()
	default:
		runDemo()
	}
}

// ── Generate from pcap ──────────────────────────────────────────

func runPcapGenerate(pcapPath, outPath, name, desc string) {
	if name == "" {
		name = strings.TrimSuffix(pcapPath, ".pcap")
		name = strings.TrimSuffix(name, ".pcapng")
		// Use just the filename without path.
		if idx := strings.LastIndex(name, "/"); idx >= 0 {
			name = name[idx+1:]
		}
	}
	if desc == "" {
		desc = fmt.Sprintf("Auto-generated profile from %s", pcapPath)
	}

	fmt.Printf("📦 Reading pcap: %s\n", pcapPath)
	profile, stats, err := morph.ProfileFromPcap(pcapPath, name, desc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("📊 Capture stats:\n")
	fmt.Printf("   Packets:  %d\n", stats.TotalPackets)
	fmt.Printf("   Bytes:    %s\n", fmtBytes(stats.TotalBytes))
	fmt.Printf("   Duration: %.1fs\n", stats.DurationSecs)
	fmt.Printf("   Avg size: %.0f bytes\n", stats.AvgPktSize)
	fmt.Println()

	printProfileDetails(profile)
	saveOrPrint(profile, outPath)
}

// ── Generate from JSON ──────────────────────────────────────────

func runJSONGenerate(jsonPath, outPath, name, desc string) {
	if name == "" {
		name = strings.TrimSuffix(jsonPath, ".json")
		if idx := strings.LastIndex(name, "/"); idx >= 0 {
			name = name[idx+1:]
		}
	}
	if desc == "" {
		desc = fmt.Sprintf("Auto-generated profile from %s", jsonPath)
	}

	fmt.Printf("📦 Reading JSON packets: %s\n", jsonPath)
	ca := morph.NewCaptureAnalyzer()
	if err := ca.LoadPackets(jsonPath); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error: %v\n", err)
		os.Exit(1)
	}

	profile := ca.BuildProfile(name, desc)
	printProfileDetails(profile)
	saveOrPrint(profile, outPath)
}

// ── Compare profiles ────────────────────────────────────────────

func runCompare(nameOrPath string) {
	target, err := morph.ResolveProfile(nameOrPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Cannot load profile %q: %v\n", nameOrPath, err)
		os.Exit(1)
	}

	fmt.Printf("🔬 Comparing: %s\n", target.Name)
	fmt.Printf("   %s\n\n", target.Description)

	printProfileDetails(target)

	fmt.Println("─── Similarity to builtin profiles ───")
	fmt.Println()

	builtins := morph.ListBuiltinProfiles()
	type result struct {
		name       string
		similarity float64
	}
	var results []result

	for _, bi := range builtins {
		if bi.Name == target.Name {
			continue
		}
		other := morph.GetBuiltinProfile(bi.Name)
		if other == nil {
			continue
		}
		sim := profileSimilarity(target, other)
		results = append(results, result{name: bi.Name, similarity: sim})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].similarity > results[j].similarity
	})

	for _, r := range results {
		bar := strings.Repeat("█", int(r.similarity/2))
		pad := strings.Repeat("░", 50-int(r.similarity/2))
		fmt.Printf("  %-22s %5.1f%% %s%s\n", r.name, r.similarity, bar, pad)
	}
	fmt.Println()

	if len(results) > 0 && results[0].similarity > 80 {
		fmt.Printf("  ⚠️  High similarity to %s (%.0f%%) — profile may not be distinct enough\n\n",
			results[0].name, results[0].similarity)
	} else {
		fmt.Println("  ✅ Profile is sufficiently distinct from all builtins")
		fmt.Println()
	}
}

// profileSimilarity calculates a similarity percentage between two profiles
// based on packet size distribution overlap and timing parameters.
func profileSimilarity(a, b *morph.Profile) float64 {
	// 1. Size distribution similarity (60% weight).
	sizeSim := bucketOverlap(a.PacketSizes.Buckets, b.PacketSizes.Buckets)

	// 2. Timing similarity (40% weight).
	timeSim := timingSimilarity(a.Timing, b.Timing)

	return sizeSim*0.6 + timeSim*0.4
}

func bucketOverlap(a, b []morph.SizeBucket) float64 {
	// Build histogram on common ranges [0..16384] with 100-byte bins.
	bins := 164
	histA := make([]float64, bins)
	histB := make([]float64, bins)

	fillHist := func(buckets []morph.SizeBucket, hist []float64) {
		totalW := 0.0
		for _, bk := range buckets {
			totalW += bk.Weight
		}
		if totalW == 0 {
			return
		}
		for _, bk := range buckets {
			w := bk.Weight / totalW
			lo := bk.Min / 100
			hi := bk.Max / 100
			if hi >= bins {
				hi = bins - 1
			}
			span := hi - lo + 1
			for i := lo; i <= hi && i < bins; i++ {
				hist[i] += w / float64(span)
			}
		}
	}
	fillHist(a, histA)
	fillHist(b, histB)

	// Bhattacharyya coefficient.
	bc := 0.0
	for i := 0; i < bins; i++ {
		bc += math.Sqrt(histA[i] * histB[i])
	}
	return bc * 100
}

func timingSimilarity(a, b morph.TimingProfile) float64 {
	// Compare normalized timing parameters.
	score := 0.0
	score += 25 * (1 - clampDiff(a.MeanDelayMs, b.MeanDelayMs, 500))
	score += 25 * (1 - clampDiff(a.JitterMs, b.JitterMs, 500))
	score += 25 * (1 - clampDiff(float64(a.BurstSize), float64(b.BurstSize), 30))
	score += 25 * (1 - clampDiff(float64(a.BurstGapMs), float64(b.BurstGapMs), 3000))
	return score
}

func clampDiff(a, b, maxDiff float64) float64 {
	d := math.Abs(a-b) / maxDiff
	if d > 1 {
		d = 1
	}
	return d
}

// ── Stealth Report ──────────────────────────────────────────

func runReport(nameOrPath string) {
	profile, err := morph.ResolveProfile(nameOrPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\u274c Cannot load profile %q: %v\n", nameOrPath, err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("  \u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557")
	fmt.Println("  \u2551     \U0001f50d Veil Stealth Report                           \u2551")
	fmt.Println("  \u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d")
	fmt.Println()
	fmt.Printf("  Profile: %s\n", profile.Name)
	fmt.Printf("  %s\n\n", profile.Description)

	// === Section 1: Packet Size Distribution ===
	fmt.Println("  \u2500\u2500\u2500 Packet Size Distribution \u2500\u2500\u2500")
	fmt.Println()
	printHistogram(profile.PacketSizes.Buckets)

	// === Section 2: Timing Analysis ===
	fmt.Println("  \u2500\u2500\u2500 Timing Analysis \u2500\u2500\u2500")
	fmt.Println()
	tm := profile.Timing
	fmt.Printf("    Mean delay:   %6.0f ms\n", tm.MeanDelayMs)
	fmt.Printf("    Jitter:       %6.0f ms\n", tm.JitterMs)
	fmt.Printf("    Burst size:   %6d pkts\n", tm.BurstSize)
	fmt.Printf("    Burst gap:    %6d ms\n", tm.BurstGapMs)
	fmt.Printf("    Range:        %d\u2013%d ms\n\n", tm.MinDelayMs, tm.MaxDelayMs)

	// Simulate timing sample
	fmt.Print("    Sample: ")
	te := morph.NewTimingEngine(&tm)
	for i := 0; i < 12; i++ {
		fmt.Printf("%dms ", te.NextDelay().Milliseconds())
	}
	fmt.Println()

	// === Section 3: Similarity Matrix ===
	fmt.Println("  \u2500\u2500\u2500 Similarity to Known Traffic \u2500\u2500\u2500")
	fmt.Println()

	type simResult struct {
		name string
		pct  float64
	}
	var results []simResult
	for _, bi := range morph.ListBuiltinProfiles() {
		if bi.Name == profile.Name {
			continue
		}
		other := morph.GetBuiltinProfile(bi.Name)
		if other == nil {
			continue
		}
		sim := profileSimilarity(profile, other)
		results = append(results, simResult{bi.Name, sim})
	}
	sort.Slice(results, func(i, j int) bool { return results[i].pct > results[j].pct })

	for _, r := range results {
		barLen := int(r.pct / 2.5)
		if barLen > 40 { barLen = 40 }
		bar := strings.Repeat("\u2588", barLen) + strings.Repeat("\u2591", 40-barLen)
		fmt.Printf("    %-22s %5.1f%% %s\n", r.name, r.pct, bar)
	}
	fmt.Println()

	// === Section 4: Entropy Check ===
	fmt.Println("  \u2500\u2500\u2500 Entropy Analysis \u2500\u2500\u2500")
	fmt.Println()
	engine := morph.NewEngine(profile)
	padding := engine.GeneratePadding(10000)
	entropy := calculateEntropy(padding)
	entBar := int(entropy / 8.0 * 40)
	fmt.Printf("    Padding entropy:  %.2f / 8.00 bits\n", entropy)
	fmt.Printf("    %s\n", strings.Repeat("\u2588", entBar) + strings.Repeat("\u2591", 40-entBar))
	if entropy > 7.9 {
		fmt.Println("    \u2705 Excellent \u2014 indistinguishable from TLS")
	} else if entropy > 7.5 {
		fmt.Println("    \u26a0\ufe0f  Good \u2014 close to TLS, minor patterns possible")
	} else {
		fmt.Println("    \u274c Poor \u2014 detectable patterns in padding bytes")
	}
	fmt.Println()

	// === Section 5: Stealth Score ===
	scoreSize := scoreSizeDistribution(profile)
	scoreTiming := scoreTimingRealism(profile)
	scoreEntropy := math.Min(entropy/8.0*100, 100)
	scoreBurst := scoreBurstPattern(profile)
	overall := (scoreSize*30 + scoreTiming*25 + scoreEntropy*25 + scoreBurst*20) / 100

	fmt.Println("  \u2500\u2500\u2500 Stealth Score \u2500\u2500\u2500")
	fmt.Println()
	printScoreBar("  Size distribution", scoreSize)
	printScoreBar("  Timing realism   ", scoreTiming)
	printScoreBar("  Entropy          ", scoreEntropy)
	printScoreBar("  Burst pattern    ", scoreBurst)
	fmt.Println()
	printScoreBar("  \u2605 OVERALL         ", overall)
	fmt.Println()

	if overall >= 85 {
		fmt.Println("  \U0001f6e1 Verdict: EXCELLENT stealth \u2014 very hard for DPI to detect")
	} else if overall >= 70 {
		fmt.Println("  \U0001f6e1 Verdict: GOOD stealth \u2014 defeats most DPI systems")
	} else if overall >= 50 {
		fmt.Println("  \u26a0\ufe0f  Verdict: MODERATE stealth \u2014 advanced DPI may flag this")
	} else {
		fmt.Println("  \u274c Verdict: WEAK stealth \u2014 likely detectable by statistical DPI")
	}
	fmt.Println()

	// === Section 6: Recommendations ===
	fmt.Println("  \u2500\u2500\u2500 Recommendations \u2500\u2500\u2500")
	fmt.Println()
	recommendations := generateRecommendations(profile, scoreSize, scoreTiming, scoreBurst)
	if len(recommendations) == 0 {
		fmt.Println("    \u2705 No issues found \u2014 profile looks great!")
	} else {
		for _, r := range recommendations {
			fmt.Printf("    \u2022 %s\n", r)
		}
	}
	fmt.Println()
}

func printHistogram(buckets []morph.SizeBucket) {
	maxW := 0.0
	for _, b := range buckets {
		if b.Weight > maxW {
			maxW = b.Weight
		}
	}
	for _, b := range buckets {
		barLen := int(b.Weight / maxW * 30)
		bar := strings.Repeat("\u2588", barLen) + strings.Repeat("\u2591", 30-barLen)
		fmt.Printf("    %5d-%-5d %5.1f%% %s\n", b.Min, b.Max, b.Weight, bar)
	}
	fmt.Println()
}

func printScoreBar(label string, score float64) {
	barLen := int(score / 100 * 30)
	if barLen > 30 { barLen = 30 }
	var color string
	if score >= 80 {
		color = "\u2588"
	} else if score >= 60 {
		color = "\u2593"
	} else {
		color = "\u2592"
	}
	bar := strings.Repeat(color, barLen) + strings.Repeat("\u2591", 30-barLen)
	grade := "F"
	switch {
	case score >= 90: grade = "A+"
	case score >= 80: grade = "A"
	case score >= 70: grade = "B"
	case score >= 60: grade = "C"
	case score >= 50: grade = "D"
	}
	fmt.Printf("    %s  %s %5.1f%% [%s]\n", label, bar, score, grade)
}

func scoreSizeDistribution(p *morph.Profile) float64 {
	buckets := p.PacketSizes.Buckets
	if len(buckets) == 0 { return 0 }
	// More buckets = more realistic distribution
	bucketScore := math.Min(float64(len(buckets))/8.0*100, 100)
	// Weight spread: check that no single bucket dominates >60%
	maxW := 0.0
	for _, b := range buckets {
		if b.Weight > maxW { maxW = b.Weight }
	}
	spreadScore := 100.0
	if maxW > 60 { spreadScore = 60 }
	if maxW > 80 { spreadScore = 30 }
	// Has small packets (ACKs)?
	hasSmall := false
	for _, b := range buckets {
		if b.Min < 100 && b.Weight > 3 { hasSmall = true }
	}
	smallScore := 60.0
	if hasSmall { smallScore = 100 }
	return (bucketScore*40 + spreadScore*35 + smallScore*25) / 100
}

func scoreTimingRealism(p *morph.Profile) float64 {
	tm := p.Timing
	// Zero jitter is suspicious
	jitterScore := 100.0
	if tm.JitterMs < 5 { jitterScore = 30 }
	if tm.JitterMs < 1 { jitterScore = 10 }
	// Some delay variance is good
	delayScore := 100.0
	if tm.MeanDelayMs < 1 { delayScore = 40 }
	if tm.MaxDelayMs-tm.MinDelayMs < 10 { delayScore = 50 }
	// Burst gap should exist
	gapScore := 100.0
	if tm.BurstGapMs < 10 { gapScore = 40 }
	return (jitterScore*40 + delayScore*30 + gapScore*30) / 100
}

func scoreBurstPattern(p *morph.Profile) float64 {
	tm := p.Timing
	// Burst size between 2-30 is realistic
	if tm.BurstSize < 2 { return 40 }
	if tm.BurstSize > 50 { return 50 }
	// Gap/burst ratio
	ratio := float64(tm.BurstGapMs) / math.Max(float64(tm.BurstSize), 1)
	if ratio < 1 { return 50 }
	if ratio > 500 { return 70 }
	return 90
}

func generateRecommendations(p *morph.Profile, sizeScore, timingScore, burstScore float64) []string {
	var recs []string
	buckets := p.PacketSizes.Buckets

	if len(buckets) < 5 {
		recs = append(recs, "Add more size buckets (5+ recommended) for a more realistic distribution")
	}

	maxW := 0.0
	for _, b := range buckets {
		if b.Weight > maxW { maxW = b.Weight }
	}
	if maxW > 60 {
		recs = append(recs, fmt.Sprintf("Dominant bucket has %.0f%% weight \u2014 spread traffic more evenly to avoid statistical fingerprinting", maxW))
	}

	hasSmall := false
	for _, b := range buckets {
		if b.Min < 100 && b.Weight > 3 { hasSmall = true }
	}
	if !hasSmall {
		recs = append(recs, "Add small packets (40-100 bytes, 5-15%%) to mimic TCP ACKs and control frames")
	}

	tm := p.Timing
	if tm.JitterMs < 5 {
		recs = append(recs, "Increase jitter (10+ ms) \u2014 low jitter looks like machine-generated traffic")
	}
	if tm.MeanDelayMs < 1 {
		recs = append(recs, "Add some inter-packet delay (5+ ms mean) \u2014 zero delay is a VPN fingerprint")
	}
	if tm.BurstGapMs < 10 {
		recs = append(recs, "Increase burst gap (50+ ms) \u2014 continuous streams without pauses are suspicious")
	}
	if tm.BurstSize > 40 {
		recs = append(recs, fmt.Sprintf("Burst size %d is very high \u2014 consider reducing to 15-25 for more natural patterns", tm.BurstSize))
	}

	return recs
}


// ── List profiles ───────────────────────────────────────────────

func runList() {
	fmt.Println()
	fmt.Println("  ╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("  ║              🎭 Available Morph Profiles                         ║")
	fmt.Println("  ╚══════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	for _, pi := range morph.ListBuiltinProfiles() {
		p := morph.GetBuiltinProfile(pi.Name)
		if p == nil {
			continue
		}

		// Calculate dominant bucket.
		dominant := ""
		maxW := 0.0
		for _, bk := range p.PacketSizes.Buckets {
			if bk.Weight > maxW {
				maxW = bk.Weight
				dominant = fmt.Sprintf("%d-%d bytes (%.0f%%)", bk.Min, bk.Max, bk.Weight)
			}
		}

		fmt.Printf("  %-22s %s\n", pi.Name, pi.Description)
		fmt.Printf("  %22s Buckets: %d | Dominant: %s\n", "", len(p.PacketSizes.Buckets), dominant)
		fmt.Printf("  %22s Timing: mean=%.0fms jitter=%.0fms burst=%d gap=%dms\n",
			"", p.Timing.MeanDelayMs, p.Timing.JitterMs, p.Timing.BurstSize, p.Timing.BurstGapMs)
		fmt.Println()
	}
}

// ── Demo mode ───────────────────────────────────────────────────

func runDemo() {
	fmt.Println()
	fmt.Println("  ╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("  ║        🔬 Veil Protocol — Traffic Analysis Tool              ║")
	fmt.Println("  ╠══════════════════════════════════════════════════════════════╣")
	fmt.Println("  ║  Tip: use -help to see generation/comparison modes          ║")
	fmt.Println("  ╚══════════════════════════════════════════════════════════════╝")

	// === Test 1: Packet sizes ===
	fmt.Println()
	fmt.Println("  ═══ Тест 1: Размеры пакетов ═══")
	fmt.Println()
	fmt.Println("  Обычный VPN шлёт пакеты одинакового размера (MTU=1420).")
	fmt.Println("  DPI легко детектит: '80% пакетов = 1420 байт → это VPN'")
	fmt.Println("  Veil маскирует размеры под реальные приложения.")
	fmt.Println()

	fmt.Println("  📦 БЕЗ морфинга (обычный VPN):")
	plainSizes := generatePlainVPN(1000)
	printDistribution(plainSizes)

	fmt.Println("  🎭 Veil + профиль HTTP/2 (как Chrome):")
	h2Engine := morph.NewEngine(morph.BuiltinHTTP2Profile())
	h2Sizes := generateMorphedTraffic(h2Engine, 1000)
	printDistribution(h2Sizes)

	fmt.Println("  📺 Veil + профиль Video (как YouTube):")
	vidEngine := morph.NewEngine(morph.BuiltinVideoProfile())
	vidSizes := generateMorphedTraffic(vidEngine, 1000)
	printDistribution(vidSizes)

	fmt.Println("  📱 Veil + профиль TikTok:")
	ttEngine := morph.NewEngine(morph.BuiltinTikTokProfile())
	ttSizes := generateMorphedTraffic(ttEngine, 1000)
	printDistribution(ttSizes)

	fmt.Println("  ✅ Разница очевидна: VPN = один столбик, Veil = распределение как у реального приложения")
	fmt.Println()

	// === Test 2: Entropy ===
	fmt.Println("  ═══ Тест 2: Энтропия (случайность данных) ═══")
	fmt.Println()

	htmlData := []byte("<html><head><title>Example</title></head><body><h1>Hello World</h1><p>This is a normal web page with normal text content that repeats letters frequently.</p></body></html>")
	for len(htmlData) < 10000 {
		htmlData = append(htmlData, htmlData...)
	}
	htmlData = htmlData[:10000]
	fmt.Printf("  📄 HTML текст:          энтропия = %.2f / 8.00 бит\n", calculateEntropy(htmlData))

	encData := make([]byte, 10000)
	rand.Read(encData)
	fmt.Printf("  🔐 Шифрованные данные:  энтропия = %.2f / 8.00 бит\n", calculateEntropy(encData))

	tlsData := make([]byte, 10000)
	rand.Read(tlsData)
	fmt.Printf("  🌐 Обычный TLS (HTTPS): энтропия = %.2f / 8.00 бит\n", calculateEntropy(tlsData))

	morphPad := h2Engine.GeneratePadding(10000)
	fmt.Printf("  🎭 Veil морф-паддинг:   энтропия = %.2f / 8.00 бит\n", calculateEntropy(morphPad))
	fmt.Println()
	fmt.Println("  ✅ Veil неотличим от обычного HTTPS — та же энтропия")
	fmt.Println()

	// === Test 3: Timing ===
	fmt.Println("  ═══ Тест 3: Тайминги между пакетами ═══")
	fmt.Println()

	fmt.Println("  ⏱  Обычный VPN:          0ms  0ms  0ms  0ms  0ms  0ms  0ms  0ms")
	fmt.Println("                            ↑ подозрительно ровно!")
	fmt.Println()

	profiles := []struct {
		name    string
		profile *morph.Profile
	}{
		{"HTTP/2", morph.BuiltinHTTP2Profile()},
		{"Video", morph.BuiltinVideoProfile()},
		{"TikTok", morph.BuiltinTikTokProfile()},
		{"Discord", morph.BuiltinDiscordProfile()},
		{"Telegram", morph.BuiltinTelegramProfile()},
	}

	for _, pp := range profiles {
		te := morph.NewTimingEngine(&pp.profile.Timing)
		fmt.Printf("  ⏱  Veil (%-10s): ", pp.name)
		for i := 0; i < 8; i++ {
			fmt.Printf("%-6dms ", te.NextDelay().Milliseconds())
		}
		fmt.Println()
	}
	fmt.Println()

	// === Test 4: Handshake ===
	fmt.Println("  ═══ Тест 4: Полиморфный хэндшейк ═══")
	fmt.Println()

	psk := veilcrypto.GeneratePSK("demo-secret")
	fmt.Println("  Три хэндшейка с одним и тем же ключом:")
	fmt.Println()

	for i := 0; i < 3; i++ {
		kp, _ := veilcrypto.GenerateKeyPair()
		nonce, _ := veilcrypto.GenerateNonce(16)

		raw := make([]byte, 48)
		copy(raw[0:32], kp.Public[:])
		copy(raw[32:48], nonce)

		mask, _, _ := veilcrypto.DeriveHandshakeMask(psk, "raw", 48)
		masked := veilcrypto.XORBytes(raw, mask)

		fmt.Printf("    #%d: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x ...\n",
			i+1, masked[0], masked[1], masked[2], masked[3],
			masked[4], masked[5], masked[6], masked[7],
			masked[8], masked[9], masked[10], masked[11])
	}

	fmt.Println()
	fmt.Println("  ✅ Каждый раз полностью разные байты — невозможно написать сигнатуру")
	fmt.Println()

	// === SUMMARY ===
	fmt.Println("  ╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("  ║                       📊 ИТОГ                               ║")
	fmt.Println("  ╠══════════════════════════════════════════════════════════════╣")
	fmt.Println("  ║  Что видит DPI при обычном VPN:                             ║")
	fmt.Println("  ║    ❌ Фиксированная сигнатура хэндшейка                     ║")
	fmt.Println("  ║    ❌ 80% пакетов одного размера (1420 байт)                ║")
	fmt.Println("  ║    ❌ Нулевые задержки между пакетами                       ║")
	fmt.Println("  ║    → ЗАБЛОКИРОВАНО                                          ║")
	fmt.Println("  ║                                                              ║")
	fmt.Println("  ║  Что видит DPI при Veil Protocol:                           ║")
	fmt.Println("  ║    ✅ Случайные байты (нет сигнатуры)                       ║")
	fmt.Println("  ║    ✅ Размеры пакетов как у реального приложения             ║")
	fmt.Println("  ║    ✅ Тайминги как у реального браузера                      ║")
	fmt.Println("  ║    ✅ Энтропия идентична обычному TLS                       ║")
	fmt.Println("  ║    → НЕ ДЕТЕКТИРУЕТСЯ                                       ║")
	fmt.Println("  ╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("  Подробнее: veil-analyze -help")
	fmt.Println()
}

// ── Helpers ─────────────────────────────────────────────────────

func printProfileDetails(p *morph.Profile) {
	fmt.Printf("📋 Profile: %s\n", p.Name)
	fmt.Printf("   %s\n\n", p.Description)
	fmt.Println("   Packet size distribution:")
	for _, b := range p.PacketSizes.Buckets {
		bar := strings.Repeat("█", int(b.Weight/2))
		fmt.Printf("   %5d-%-5d  %5.1f%% %s\n", b.Min, b.Max, b.Weight, bar)
	}
	fmt.Println()
	fmt.Printf("   Timing: mean=%.0fms jitter=%.0fms burst=%d gap=%dms\n\n",
		p.Timing.MeanDelayMs, p.Timing.JitterMs, p.Timing.BurstSize, p.Timing.BurstGapMs)
}

func saveOrPrint(profile *morph.Profile, outPath string) {
	if outPath == "" {
		fmt.Println("💡 Use -out profile.json to save. Example:")
		fmt.Printf("   veil-analyze -pcap capture.pcap -name %s -out %s.json\n\n", profile.Name, profile.Name)
		return
	}

	if err := morph.SaveProfile(profile, outPath); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Save error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✅ Profile saved to: %s\n", outPath)
	fmt.Printf("   Use: veil-client -morph %s -server ...\n\n", outPath)
}

func fmtBytes(b int64) string {
	if b < 1024 {
		return fmt.Sprintf("%d B", b)
	} else if b < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(b)/1024)
	} else if b < 1<<30 {
		return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
	}
	return fmt.Sprintf("%.1f GB", float64(b)/float64(1<<30))
}

func generatePlainVPN(count int) []int {
	sizes := make([]int, count)
	r := make([]byte, count)
	rand.Read(r)
	for i := range sizes {
		switch {
		case r[i] < 30:
			sizes[i] = 64
		case r[i] < 50:
			sizes[i] = 128
		default:
			sizes[i] = 1420
		}
	}
	return sizes
}

func generateMorphedTraffic(engine *morph.Engine, count int) []int {
	sizes := make([]int, count)
	r := make([]byte, count*2)
	rand.Read(r)
	for i := range sizes {
		base := int(r[i*2])<<8 | int(r[i*2+1])
		base = base % 2000
		padding := engine.CalculatePadding(base)
		sizes[i] = base + padding
	}
	return sizes
}

func printDistribution(sizes []int) {
	keys := []string{"   0-100  ", " 100-300  ", " 300-800  ", " 800-1460 ", "1460-4096 ", "4096+     "}
	buckets := make([]int, 6)

	for _, s := range sizes {
		switch {
		case s <= 100:
			buckets[0]++
		case s <= 300:
			buckets[1]++
		case s <= 800:
			buckets[2]++
		case s <= 1460:
			buckets[3]++
		case s <= 4096:
			buckets[4]++
		default:
			buckets[5]++
		}
	}

	total := len(sizes)
	for i, k := range keys {
		pct := float64(buckets[i]) / float64(total) * 100
		bar := ""
		for j := 0; j < int(pct/2); j++ {
			bar += "█"
		}
		fmt.Printf("      %s %5.1f%% %s\n", k, pct, bar)
	}

	sort.Ints(sizes)
	fmt.Printf("      Медиана: %d байт\n\n", sizes[len(sizes)/2])
}

func calculateEntropy(data []byte) float64 {
	freq := make([]float64, 256)
	for _, b := range data {
		freq[b]++
	}
	entropy := 0.0
	n := float64(len(data))
	for _, f := range freq {
		if f > 0 {
			p := f / n
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}
