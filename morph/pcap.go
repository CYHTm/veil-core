// Package morph — pcap.go provides a pure-Go pcap file reader.
// No external dependencies (no libpcap/gopacket required).
//
// Supports standard pcap format (both little-endian and big-endian),
// microsecond and nanosecond timestamp resolution.
package morph

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

const (
	pcapMagicMicros = 0xa1b2c3d4 // Standard pcap, microsecond timestamps
	pcapMagicNanos  = 0xa1b23c4d // Standard pcap, nanosecond timestamps
	pcapMagicSwap   = 0xd4c3b2a1 // Swapped byte order, microsecond
	pcapMagicNSwap  = 0x4d3cb2a1 // Swapped byte order, nanosecond

	// Ethernet header size (MACs + EtherType).
	ethHeaderSize = 14
	// Minimum IPv4 header size.
	ipv4MinHeader = 20
)

// pcapGlobalHeader is the 24-byte file header of a pcap file.
type pcapGlobalHeader struct {
	MagicNumber  uint32
	VersionMajor uint16
	VersionMinor uint16
	ThisZone     int32
	SigFigs      uint32
	SnapLen      uint32
	Network      uint32 // 1 = Ethernet, 101 = Raw IP
}

// pcapPacketHeader is the 16-byte per-packet header.
type pcapPacketHeader struct {
	TsSec   uint32
	TsUsec  uint32
	InclLen uint32
	OrigLen uint32
}

// PcapStats holds summary statistics from a pcap read.
type PcapStats struct {
	TotalPackets int
	TotalBytes   int64
	DurationSecs float64
	AvgPktSize   float64
}

// ReadPcapFile reads a pcap file and returns packet records suitable
// for CaptureAnalyzer. Pure Go, no libpcap dependency.
func ReadPcapFile(path string) ([]PacketRecord, *PcapStats, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	// Detect byte order from magic number.
	var magic uint32
	if err := binary.Read(f, binary.LittleEndian, &magic); err != nil {
		return nil, nil, fmt.Errorf("read magic: %w", err)
	}

	var byteOrder binary.ByteOrder
	var nanoRes bool

	switch magic {
	case pcapMagicMicros:
		byteOrder = binary.LittleEndian
	case pcapMagicNanos:
		byteOrder = binary.LittleEndian
		nanoRes = true
	case pcapMagicSwap:
		byteOrder = binary.BigEndian
	case pcapMagicNSwap:
		byteOrder = binary.BigEndian
		nanoRes = true
	default:
		return nil, nil, fmt.Errorf("not a pcap file (magic: 0x%08x)", magic)
	}

	// Re-read full global header with correct byte order.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, nil, err
	}
	var ghdr pcapGlobalHeader
	if err := binary.Read(f, byteOrder, &ghdr); err != nil {
		return nil, nil, fmt.Errorf("read global header: %w", err)
	}

	var records []PacketRecord
	var startTime float64
	var totalBytes int64
	first := true

	for {
		var phdr pcapPacketHeader
		if err := binary.Read(f, byteOrder, &phdr); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return nil, nil, fmt.Errorf("read packet header: %w", err)
		}

		// Calculate timestamp.
		ts := float64(phdr.TsSec)
		if nanoRes {
			ts += float64(phdr.TsUsec) / 1e9
		} else {
			ts += float64(phdr.TsUsec) / 1e6
		}

		if first {
			startTime = ts
			first = false
		}

		// Determine payload size (strip Ethernet + IP headers if present).
		payloadSize := int(phdr.OrigLen)
		if ghdr.Network == 1 && payloadSize > ethHeaderSize+ipv4MinHeader {
			// Ethernet link layer — report IP-level size.
			payloadSize -= ethHeaderSize
		}

		// Skip the captured packet data in the file.
		if _, err := io.CopyN(io.Discard, f, int64(phdr.InclLen)); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return nil, nil, fmt.Errorf("skip packet data: %w", err)
		}

		totalBytes += int64(phdr.OrigLen)
		records = append(records, PacketRecord{
			Size:      payloadSize,
			Timestamp: ts - startTime,
			Direction: 0, // Direction requires IP address filtering
		})
	}

	duration := 0.0
	avgSize := 0.0
	if len(records) > 0 {
		duration = records[len(records)-1].Timestamp
		avgSize = float64(totalBytes) / float64(len(records))
	}

	stats := &PcapStats{
		TotalPackets: len(records),
		TotalBytes:   totalBytes,
		DurationSecs: duration,
		AvgPktSize:   avgSize,
	}

	return records, stats, nil
}

// ProfileFromPcap generates a morph profile directly from a pcap file.
func ProfileFromPcap(pcapPath, name, description string) (*Profile, *PcapStats, error) {
	records, stats, err := ReadPcapFile(pcapPath)
	if err != nil {
		return nil, nil, err
	}
	if len(records) == 0 {
		return nil, nil, fmt.Errorf("no packets found in %s", pcapPath)
	}

	ca := NewCaptureAnalyzer()
	for _, r := range records {
		ca.AddPacket(r.Size, r.Timestamp, r.Direction)
	}

	profile := ca.BuildProfile(name, description)
	return profile, stats, nil
}
