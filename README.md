<div align="center">

<img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square&logo=go" alt="Go">
<img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License">
<img src="https://img.shields.io/badge/Tests-36%20passed-brightgreen?style=flat-square" alt="Tests">
<img src="https://img.shields.io/badge/Status-Alpha-orange?style=flat-square" alt="Status">

# Veil Protocol

**Stealth tunneling protocol with traffic morphing**

*Your traffic looks like Netflix. Not like a VPN.*

[English](#overview) · [Русский](#обзор)

</div>

---

## Overview

Veil is a next-generation tunneling protocol designed to be undetectable by Deep Packet Inspection (DPI) systems. Unlike traditional VPNs and proxies that can be fingerprinted and blocked, Veil makes tunnel traffic statistically indistinguishable from legitimate applications.

### How DPI blocks existing tools

| What DPI sees | VPN/Proxy | Veil |
|---|---|---|
| Handshake pattern | Fixed signature → **blocked** | Polymorphic — changes every 30 seconds |
| Packet sizes | Uniform (MTU-aligned) → **detected** | Mimics real Chrome/YouTube distribution |
| Timing | Zero delays → **suspicious** | Jitter engine simulates real user behavior |
| TLS fingerprint | Go/Python client → **flagged** | uTLS mimics Chrome/Firefox/Safari exactly |
| Server probe | Proxy response → **blocked** | Real website (Protocol Completion) |

### Key Features

- **Traffic Morphing** — packets statistically match HTTP/2, YouTube, gRPC profiles
- **Polymorphic Handshake** — every connection looks completely different
- **uTLS Browser Mimicry** — DPI sees Chrome 120, not a Go client
- **Protocol Completion** — server runs a real website, tunnel activates via steganographic trigger
- **Timing Jitter Engine** — artificial delays mimic real browsing patterns
- **ChaCha20-Poly1305 / AES-256-GCM** encryption
- **X25519 ECDH** key exchange with HKDF
- **Multiplexed streams** — 256 concurrent connections over single tunnel
- **Pluggable transports** — Raw TCP, TLS 1.3, WebSocket

## Quick Start

### Server (on your VPS)

One command:
curl -fsSL https://raw.githubusercontent.com/CYHTm/veil-core/main/install/server.sh | sudo bash


The script will:
- Install dependencies and build Veil
- Create a systemd service (auto-start on boot)
- Generate a secret key
- Configure the firewall
- Print a connection link for clients

### Client

1. Download from [Releases](https://github.com/CYHTm/veil-core/releases)
2. Run `veil-app`
3. Paste the link from server owner
4. Click "Connect"

Or via terminal:
./veil-client -server IP:PORT -secret "SECRET"


### Connection Link

Server owners share a link:
veil://SECRET@IP:PORT?transport=tls&morph=http2_browsing


Clients paste it — all settings apply automatically.

## Architecture
veil-core/ ├── protocol/ Polymorphic handshake, frames, sessions, state machine ├── crypto/ X25519, ChaCha20, HKDF, steganographic triggers ├── transport/ Pluggable: Raw TCP, TLS 1.3 (uTLS), WebSocket ├── morph/ Traffic morphing engine + real browser profiles ├── mux/ Stream multiplexer (256 concurrent streams) ├── api/ Client/Server API, veil:// links, system proxy └── cmd/ Server, client, GUI app, traffic analyzer


## Build from Source
git clone https://github.com/CYHTm/veil-core.git cd veil-core go build -o bin/veil-server ./cmd/veil-server/ go build -o bin/veil-client ./cmd/veil-client/ go build -o bin/veil-app ./cmd/veil-app/

## Tests
go test ./... -v


36 tests covering cryptography, frames, morphing, multiplexer, and security (replay attacks, tamper detection, key randomness).

---

## Обзор

Veil — протокол туннелирования нового поколения, невидимый для систем DPI. В отличие от обычных VPN и прокси, трафик Veil статистически неотличим от легитимных приложений.

### Как DPI блокирует существующие инструменты

| Что видит DPI | VPN/Прокси | Veil |
|---|---|---|
| Хэндшейк | Фиксированная сигнатура → **блок** | Полиморфный — меняется каждые 30 сек |
| Размеры пакетов | Одинаковые (MTU) → **детект** | Имитация Chrome/YouTube |
| Тайминги | Нулевые задержки → **подозрительно** | Jitter engine как у браузера |
| TLS отпечаток | Go/Python клиент → **флаг** | uTLS имитирует Chrome/Firefox |
| Проверка сервера | Ответ прокси → **блок** | Настоящий сайт |

### Быстрый старт

**Сервер** (на VPS за границей):
curl -fsSL https://raw.githubusercontent.com/CYHTm/veil-core/main/install/server.sh | sudo bash


**Клиент**: скачай из [Releases](https://github.com/CYHTm/veil-core/releases), вставь ссылку, подключись.

### Сборка
git clone https://github.com/CYHTm/veil-core.git cd veil-core go build -o bin/veil-server ./cmd/veil-server/ go build -o bin/veil-client ./cmd/veil-client/ go build -o bin/veil-app ./cmd/veil-app/


---

## License

MIT

