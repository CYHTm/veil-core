package morph

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// writeDummyPcap creates a minimal valid pcap file for testing.
func writeDummyPcap(t *testing.T, path string, packetSizes []int) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create pcap: %v", err)
	}
	defer f.Close()

	// Write global header (little-endian, microsecond, Ethernet).
	ghdr := pcapGlobalHeader{
		MagicNumber:  pcapMagicMicros,
		VersionMajor: 2,
		VersionMinor: 4,
		ThisZone:     0,
		SigFigs:      0,
		SnapLen:      65535,
		Network:      1, // Ethernet
	}
	binary.Write(f, binary.LittleEndian, &ghdr)

	// Write packets with incrementing timestamps.
	for i, size := range packetSizes {
		phdr := pcapPacketHeader{
			TsSec:   uint32(1000 + i),
			TsUsec:  uint32(i * 100000),
			InclLen: uint32(size),
			OrigLen: uint32(size),
		}
		binary.Write(f, binary.LittleEndian, &phdr)
		// Write dummy packet data.
		data := make([]byte, size)
		f.Write(data)
	}
}

func TestReadPcapFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pcap")
	sizes := []int{100, 500, 1460, 200, 800}
	writeDummyPcap(t, path, sizes)

	records, stats, err := ReadPcapFile(path)
	if err != nil {
		t.Fatalf("ReadPcapFile: %v", err)
	}
	if len(records) != len(sizes) {
		t.Fatalf("expected %d records, got %d", len(sizes), len(records))
	}
	if stats.TotalPackets != len(sizes) {
		t.Errorf("stats.TotalPackets = %d, want %d", stats.TotalPackets, len(sizes))
	}
	if stats.TotalBytes == 0 {
		t.Error("stats.TotalBytes is 0")
	}

	// First record timestamp should be 0 (relative).
	if records[0].Timestamp != 0 {
		t.Errorf("first record timestamp = %f, want 0", records[0].Timestamp)
	}

	// Timestamps should be increasing.
	for i := 1; i < len(records); i++ {
		if records[i].Timestamp <= records[i-1].Timestamp {
			t.Errorf("timestamp[%d]=%f <= timestamp[%d]=%f",
				i, records[i].Timestamp, i-1, records[i-1].Timestamp)
		}
	}
}

func TestReadPcapFileBigEndian(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "be.pcap")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}

	// Write big-endian pcap.
	ghdr := pcapGlobalHeader{
		MagicNumber:  pcapMagicMicros,
		VersionMajor: 2, VersionMinor: 4,
		SnapLen: 65535, Network: 101, // Raw IP
	}
	binary.Write(f, binary.BigEndian, &ghdr)

	// Write one packet.
	phdr := pcapPacketHeader{TsSec: 1000, TsUsec: 0, InclLen: 100, OrigLen: 100}
	binary.Write(f, binary.BigEndian, &phdr)
	f.Write(make([]byte, 100))
	f.Close()

	records, _, err := ReadPcapFile(path)
	if err != nil {
		t.Fatalf("ReadPcapFile big-endian: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	// Raw IP link type: no ethernet header stripped.
	if records[0].Size != 100 {
		t.Errorf("size = %d, want 100", records[0].Size)
	}
}

func TestReadPcapFileNotExist(t *testing.T) {
	_, _, err := ReadPcapFile("/nonexistent/file.pcap")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestReadPcapFileInvalidMagic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pcap")
	os.WriteFile(path, []byte("this is not a pcap file at all!"), 0644)

	_, _, err := ReadPcapFile(path)
	if err == nil {
		t.Error("expected error for invalid magic")
	}
}

func TestReadPcapFileEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.pcap")

	// Write only global header, no packets.
	f, _ := os.Create(path)
	ghdr := pcapGlobalHeader{
		MagicNumber: pcapMagicMicros, VersionMajor: 2, VersionMinor: 4,
		SnapLen: 65535, Network: 1,
	}
	binary.Write(f, binary.LittleEndian, &ghdr)
	f.Close()

	records, stats, err := ReadPcapFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("expected 0 records, got %d", len(records))
	}
	if stats.TotalPackets != 0 {
		t.Errorf("expected 0 total packets, got %d", stats.TotalPackets)
	}
}

func TestProfileFromPcap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.pcap")

	// Generate realistic-ish packet sizes.
	sizes := make([]int, 200)
	for i := range sizes {
		switch {
		case i%5 == 0:
			sizes[i] = 66 // ACKs
		case i%3 == 0:
			sizes[i] = 350 // Medium
		default:
			sizes[i] = 1400 // Near-MTU
		}
	}
	writeDummyPcap(t, path, sizes)

	profile, stats, err := ProfileFromPcap(path, "test_capture", "Test capture profile")
	if err != nil {
		t.Fatalf("ProfileFromPcap: %v", err)
	}

	if profile.Name != "test_capture" {
		t.Errorf("name = %q, want test_capture", profile.Name)
	}
	if len(profile.PacketSizes.Buckets) == 0 {
		t.Error("no size buckets generated")
	}
	if profile.Timing.BurstSize < 1 {
		t.Error("burst size < 1")
	}
	if stats.TotalPackets != 200 {
		t.Errorf("stats packets = %d, want 200", stats.TotalPackets)
	}

	t.Logf("Generated profile: %d buckets, burst=%d, mean_delay=%.1fms",
		len(profile.PacketSizes.Buckets), profile.Timing.BurstSize, profile.Timing.MeanDelayMs)
}

func TestProfileFromPcapNotExist(t *testing.T) {
	_, _, err := ProfileFromPcap("/nonexistent.pcap", "x", "x")
	if err == nil {
		t.Error("expected error")
	}
}

func TestPcapNanosecondResolution(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nano.pcap")

	f, _ := os.Create(path)
	ghdr := pcapGlobalHeader{
		MagicNumber: pcapMagicNanos, VersionMajor: 2, VersionMinor: 4,
		SnapLen: 65535, Network: 101,
	}
	binary.Write(f, binary.LittleEndian, &ghdr)

	// Two packets 500ms apart (nanosecond resolution).
	phdr1 := pcapPacketHeader{TsSec: 1000, TsUsec: 0, InclLen: 80, OrigLen: 80}
	binary.Write(f, binary.LittleEndian, &phdr1)
	f.Write(make([]byte, 80))

	phdr2 := pcapPacketHeader{TsSec: 1000, TsUsec: 500000000, InclLen: 120, OrigLen: 120}
	binary.Write(f, binary.LittleEndian, &phdr2)
	f.Write(make([]byte, 120))
	f.Close()

	records, _, err := ReadPcapFile(path)
	if err != nil {
		t.Fatalf("ReadPcapFile nano: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}

	// Second timestamp should be ~0.5 seconds.
	diff := records[1].Timestamp - records[0].Timestamp
	if diff < 0.4 || diff > 0.6 {
		t.Errorf("timestamp diff = %f, want ~0.5", diff)
	}
}

func TestReadPcapEthernetStripping(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eth.pcap")

	// Ethernet pcap: sizes should have 14 bytes stripped.
	sizes := []int{100, 1514} // 1514 = 1500 IP + 14 Eth
	writeDummyPcap(t, path, sizes)

	records, _, err := ReadPcapFile(path)
	if err != nil {
		t.Fatalf("ReadPcapFile: %v", err)
	}

	// 100 bytes: 100 - 14 = 86 (above threshold of ethHeader+ipMinHeader=34).
	if records[0].Size != 86 {
		t.Errorf("record[0].Size = %d, want 86", records[0].Size)
	}
	// 1514 bytes: 1514 - 14 = 1500.
	if records[1].Size != 1500 {
		t.Errorf("record[1].Size = %d, want 1500", records[1].Size)
	}
}
