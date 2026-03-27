# Contributing to Veil Protocol

## How to help

### 1. Test against real DPI
If you have a VPS in a country with internet censorship, test Veil and report results.

### 2. Improve traffic morphing profiles
Capture real browser traffic with tcpdump and create new morph profiles.

### 3. Add new transports
Implement the `transport.Transport` interface for QUIC, DNS-over-HTTPS, or other protocols.

### 4. Security audit
Review the cryptographic implementation in `crypto/` package.

### 5. Bug reports
Open an issue with steps to reproduce.

## Development

    git clone https://github.com/CYHTm/veil-core.git
    cd veil-core
    go test ./...
    go build ./...

## Code style

- English comments only
- Run `go vet ./...` before committing
- Add tests for new features
