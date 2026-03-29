<div align="center">

<br>

<img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go">
<img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
<img src="https://img.shields.io/badge/Tests-93%20passed-brightgreen?style=for-the-badge" alt="Tests">
<img src="https://img.shields.io/badge/Version-0.1.0-blue?style=for-the-badge" alt="Version">
<img src="https://img.shields.io/badge/Status-Alpha-orange?style=for-the-badge" alt="Status">

<br><br>

# 🛡 VEIL PROTOCOL

### Your traffic looks like Netflix. Not like a VPN.

*Next-generation stealth tunneling protocol with polymorphic handshakes, traffic morphing, and protocol completion — designed to be invisible to Deep Packet Inspection.*

<br>

**[Get Started](#-quick-start)** · **[How It Works](#-how-it-works)** · **[Install Server](#-server-installation)** · **[Download Client](#-client)** · **[Русский](#-veil-protocol-1)**

<br>

---

</div>

<br>

## 🔍 The Problem

Every day, millions of people lose access to the free internet. VPNs get blocked. Shadowsocks gets detected. VLESS gets fingerprinted.

**Why?** Because DPI (Deep Packet Inspection) systems have learned to recognize these tools:

| What DPI Analyzes | Traditional Tools | Result |
|:---|:---|:---|
| 🔎 Handshake bytes | Same signature every time | **Detected & blocked** |
| 📏 Packet sizes | Uniform, MTU-aligned | **Statistically flagged** |
| ⏱ Timing patterns | Zero delay between packets | **Machine-learning flagged** |
| 🔒 TLS fingerprint | Go/Python TLS library | **Fingerprinted & blocked** |
| 🌐 Server probing | Responds as proxy | **Confirmed & blocked** |

<br>

## ✨ The Solution

Veil takes a fundamentally different approach. Instead of hiding — **we blend in.**

| What DPI Sees | With Veil |
|:---|:---|
| 🔎 Handshake bytes | **Random bytes that change every 30 seconds** — no signature exists |
| 📏 Packet sizes | **Matches real Chrome / YouTube distributions** — statistically identical |
| ⏱ Timing patterns | **Artificial jitter mimics real browsing** — indistinguishable from human |
| 🔒 TLS fingerprint | **uTLS clones Chrome 120 exactly** — DPI sees a real browser |
| 🌐 Server probing | **Real website responds** — tunnel hidden behind steganographic trigger |

<br>

## 🏗 How It Works

```
  YOU                        YOUR VPS (abroad)                  INTERNET
  ───                        ────────────────                   ────────

  Browser                    Veil Server                        │
                  ┌──────────────────────┐                      │
                  │    Real Website       │                      │
                  │  "CloudMatrix Inc."   │                      │
  Veil Client     │                      │                      │
                  │ ┌────────────────┐   │                      │
   TLS 1.3        │ │ Hidden Tunnel  │   │   ✅ YouTube         │
  (Chrome FP)     │ │                │   │                      │
  ───────────────▶│ │  Activated by  │   │──▶ ✅ Google         │
  Cookie: _ga=... │ │ stego trigger  │   │                      │
  (stego trigger) │ └────────────────┘   │   ✅ Twitter         │
                  └──────────────────────┘                      │
                                                                │
  DPI sees: "Normal HTTPS request to a corporate website"       │
  DPI verdict: ✅ ALLOWED                                       │
```

<br>

## ⚡ Key Features

| Feature | Description |
|:---|:---|
| **Polymorphic Handshake** | Every connection looks completely different. Handshake changes every 30 seconds. Variable length (66–178 bytes). No static signature possible. |
| **Traffic Morphing** | Packet sizes follow real Chrome / YouTube / gRPC statistical distributions. Built from actual pcap captures. |
| **uTLS Browser Mimicry** | TLS fingerprint is identical to Chrome, Firefox, Safari, or Edge. Rotates between browsers per connection. |
| **Protocol Completion** | Server runs a real HTTPS website. Censors see legitimate content. Tunnel activates only via steganographic trigger hidden in cookies. |
| **Timing Jitter Engine** | Artificial delays mimic real human browsing patterns — burst downloads, think time, TCP slow start. |
| **Replay Protection** | Sliding window filter (1024 entries) rejects replayed packets. |
| **Split Tunneling** | Route only blocked traffic through tunnel. Local and trusted traffic goes direct. |
| **Subscriptions** | Server list URL with auto-update. Best server selection by latency. |
| **Auto Reconnect** | Exponential backoff with jitter. Automatic recovery from network drops. |
| **Multi-Platform** | Linux, Windows, macOS. Server + CLI client + GUI app. |

<br>

## 🔐 Security

| Layer | Implementation |
|:---|:---|
| Key Exchange | X25519 ECDH (same as Signal, WireGuard) |
| Encryption | ChaCha20-Poly1305 or AES-256-GCM |
| Key Derivation | HKDF-SHA256 (RFC 5869) |
| Authentication | AEAD — tamper-proof, every frame authenticated |
| Anti-Replay | Sliding window bitmap (1024 sequence numbers) |
| Timing Resistance | Constant-time comparisons, padded error responses |
| Key Hygiene | Explicit memory zeroing of secret material |
| Certificate Pinning | SHA256-SPKI hash verification |
| PSK Rotation | Automatic key rotation with grace period |
| Brute-Force Protection | Token bucket rate limiter per IP |

<br>

## 📊 Performance

Benchmarked on a standard laptop:

| Operation | Speed | Allocations |
|:---|:---|:---|
| ChaCha20-Poly1305 encrypt | **475 MB/s** | 2 allocs/op |
| AES-256-GCM encrypt | **835 MB/s** | 2 allocs/op |
| ECDH key exchange | **9,111 ops/sec** | 8 allocs/op |
| Replay filter check | **53M ops/sec** | 0 allocs/op |
| Morph padding calc | **22M ops/sec** | 0 allocs/op |
| Frame marshal | **2,200 MB/s** | 1 alloc/op |

> Crypto and morphing are **not** the bottleneck. Speed is limited only by your network.

<br>

## 🚀 Quick Start

### 🖥 Server Installation

You need a VPS outside of censored regions. Any Linux server works.

**One command:**

```bash
curl -fsSL https://raw.githubusercontent.com/CYHTm/veil-core/main/install/server.sh | sudo bash
```

What it does automatically:

- ✅ Installs Go and dependencies
- ✅ Builds veil-server from source
- ✅ Creates systemd service (survives reboot)
- ✅ Generates a random secret key
- ✅ Opens firewall port
- ✅ Prints a connection link for your friends

After installation you'll see:

```
  ✅ Veil server installed and running!

  Connection link:
  veil://aBcDeFgHiJkLmNoPqRsT@123.45.67.89:443

  Send this link to your clients.
```

Server management:

```bash
sudo systemctl status veil-server    # Check status
sudo systemctl restart veil-server   # Restart
sudo systemctl stop veil-server      # Stop
sudo journalctl -u veil-server -f    # View logs
```

<br>

## 📱 Client

### Option A: GUI App (easiest)

1. Download `veil-app-linux-amd64` from [Releases](https://github.com/CYHTm/veil-core/releases)
2. Make executable: `chmod +x veil-app-linux-amd64`
3. Run: `./veil-app-linux-amd64`
4. Browser opens automatically
5. Click **"Import Link"**
6. Paste the `veil://...` link from server owner
7. Click **"Connect"**
8. Done. Configure your browser to use SOCKS5 proxy `127.0.0.1:1080`

### Option B: Terminal

```bash
./veil-client -server 123.45.67.89:443 -secret "your-secret" -transport decoy -insecure
```

### Option C: Config File

```bash
./veil-client -config client.json
```

Example `client.json`:

```json
{
  "server": "123.45.67.89:443",
  "secret": "your-secret",
  "transport": "decoy",
  "cipher": "chacha20-poly1305",
  "socks": "127.0.0.1:1080",
  "morph": "http2_browsing"
}
```

<br>

## 🌐 Browser Setup

After the client is connected, configure your browser:

**Firefox:**

1. Settings → Network Settings → Manual proxy configuration
2. SOCKS Host: `127.0.0.1` — Port: `1080`
3. Select **SOCKS v5**
4. Check **"Proxy DNS when using SOCKS v5"**

**Chrome:**

```bash
google-chrome --proxy-server="socks5://127.0.0.1:1080"
```

**System-wide (GNOME):**

1. Settings → Network → Proxy → Manual
2. Socks Host: `127.0.0.1:1080`

<br>

## 🔗 Connection Links

Veil uses shareable links (like VLESS / Shadowsocks):

```
veil://SECRET@HOST:PORT?transport=decoy&morph=http2_browsing&sni=cdn.example.com
```

| Parameter | Values | Default |
|:---|:---|:---|
| `transport` | `raw`, `tls`, `wss`, `decoy` | `tls` |
| `morph` | `http2_browsing`, `video_streaming` | `http2_browsing` |
| `cipher` | `chacha20-poly1305`, `aes-256-gcm` | `chacha20-poly1305` |
| `sni` | Any domain name | Server hostname |

<br>

## 🏛 Architecture

```
veil-core/
├── protocol/          Polymorphic handshake, frames, sessions, state machine
├── crypto/            X25519, ChaCha20, HKDF, steganography, replay filter,
│                      rate limiter, cert pinning, PSK rotation, memory zeroing
├── transport/
│   ├── raw/           Plain TCP (testing only)
│   ├── tls/           TLS 1.3 with uTLS browser mimicry + fingerprint rotation
│   ├── wss/           WebSocket over TLS
│   ├── decoy/         Protocol Completion (HTTP trigger → tunnel)
│   └── fragment.go    TCP-level fragmentation against DPI reassembly
├── morph/
│   ├── engine.go      Traffic morphing engine
│   ├── timing.go      Timing jitter engine
│   ├── sequence.go    Directional sequence morphing
│   ├── capture.go     Build profiles from real pcap captures
│   └── profiles/      Chrome, YouTube, gRPC statistical profiles
├── mux/               Stream multiplexer (256 concurrent, flow control)
├── api/
│   ├── client.go      Base client
│   ├── server.go      Base server
│   ├── decoy.go       Protocol Completion server (real website + hidden tunnel)
│   ├── managed_client.go  Production client (reconnect, timeouts, recovery)
│   ├── subscription.go    Server list subscriptions with auto-update
│   ├── split.go       Split tunneling (whitelist / blacklist)
│   ├── link.go        veil:// link generation and parsing
│   └── events.go      Event system for UI integration
├── cmd/
│   ├── veil-server/   Server binary
│   ├── veil-client/   CLI client binary
│   ├── veil-app/      GUI app (web-based UI with EN/RU)
│   └── veil-analyze/  Traffic analysis tool
├── install/           One-command server install script
├── configs/           Example configuration files
├── DISCLAIMER.md      Legal disclaimer (EN/RU)
└── LICENSE            MIT License
```

<br>

## 🛠 Build from Source

**Requirements:** Go 1.21+

```bash
git clone https://github.com/CYHTm/veil-core.git
cd veil-core

# Build everything
go build -o bin/veil-server ./cmd/veil-server/
go build -o bin/veil-client ./cmd/veil-client/
go build -o bin/veil-app ./cmd/veil-app/

# Run tests
go test ./...

# Run benchmarks
go test ./crypto/ -bench=. -benchmem
```

**Cross-compile:**

```bash
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o veil-server ./cmd/veil-server/
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o veil-client.exe ./cmd/veil-client/
GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o veil-client-macos ./cmd/veil-client/
```

<br>

## 🤝 Contributing

We need help with:

- **Testing against real DPI** — if you have a VPS in a censored country, test and report
- **Traffic profiles** — capture real browser traffic and build new morph profiles
- **New transports** — QUIC/HTTP3, DNS-over-HTTPS steganographic channel
- **Security audit** — review cryptographic implementation
- **Mobile clients** — Android / iOS apps

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

<br>

## ⚠️ Disclaimer

This software is provided for educational and research purposes. See [DISCLAIMER.md](DISCLAIMER.md).

<br>

---

<div align="center">

<br>

# 🛡 VEIL PROTOCOL

### Ваш трафик выглядит как Netflix. Не как VPN.

*Протокол туннелирования нового поколения с полиморфными хэндшейками, морфингом трафика и маскировкой под реальный сайт — невидимый для систем DPI.*

<br>

</div>

## 🔍 Проблема

Каждый день миллионы людей теряют доступ к свободному интернету. VPN блокируют. Shadowsocks детектят. VLESS снимают отпечатки.

**Почему?** Системы DPI (глубокий анализ пакетов) научились распознавать эти инструменты:

| Что анализирует DPI | Традиционные инструменты | Результат |
|:---|:---|:---|
| 🔎 Байты хэндшейка | Одинаковая сигнатура каждый раз | **Обнаружен и заблокирован** |
| 📏 Размеры пакетов | Одинаковые, выровнены по MTU | **Статистический флаг** |
| ⏱ Тайминги | Нулевые задержки между пакетами | **Машинное обучение → флаг** |
| 🔒 TLS отпечаток | Библиотека Go / Python | **Отпечаток → блок** |
| 🌐 Проверка сервера | Отвечает как прокси | **Подтверждён → блок** |

<br>

## ✨ Решение

Veil использует принципиально другой подход. Вместо того чтобы прятаться — **мы сливаемся с толпой.**

| Что видит DPI | С Veil |
|:---|:---|
| 🔎 Байты хэндшейка | **Случайные байты, меняются каждые 30 секунд** — сигнатуры не существует |
| 📏 Размеры пакетов | **Совпадают с распределением реального Chrome / YouTube** — статистически идентичны |
| ⏱ Тайминги | **Искусственный джиттер имитирует реальный сёрфинг** — неотличим от человека |
| 🔒 TLS отпечаток | **uTLS клонирует Chrome 120 в точности** — DPI видит настоящий браузер |
| 🌐 Проверка сервера | **Отвечает настоящий сайт** — туннель спрятан за стеганографическим триггером |

<br>

## 🚀 Быстрый старт

### 🖥 Установка сервера

Нужен VPS за пределами цензурируемых регионов. Подойдёт любой Linux.

**Одна команда:**

```bash
curl -fsSL https://raw.githubusercontent.com/CYHTm/veil-core/main/install/server.sh | sudo bash
```

Скрипт автоматически:

- ✅ Установит Go и зависимости
- ✅ Соберёт veil-server из исходников
- ✅ Создаст systemd сервис (переживёт перезагрузку)
- ✅ Сгенерирует случайный секрет
- ✅ Откроет порт в фаерволе
- ✅ Выведет ссылку для подключения

**Управление сервером:**

```bash
sudo systemctl status veil-server    # Статус
sudo systemctl restart veil-server   # Перезапуск
sudo systemctl stop veil-server      # Остановка
sudo journalctl -u veil-server -f    # Логи
```

<br>

## 📱 Клиент

### Вариант А: GUI приложение (проще всего)

1. Скачайте `veil-app-linux-amd64` из [Releases](https://github.com/CYHTm/veil-core/releases)
2. Сделайте исполняемым: `chmod +x veil-app-linux-amd64`
3. Запустите: `./veil-app-linux-amd64`
4. Браузер откроется автоматически
5. Нажмите **«Импортировать»**
6. Вставьте ссылку `veil://...` от владельца сервера
7. Нажмите **«Подключиться»**
8. Готово. Настройте браузер на SOCKS5 прокси `127.0.0.1:1080`

### Вариант Б: Терминал

```bash
./veil-client -server 123.45.67.89:443 -secret "ваш-секрет" -transport decoy -insecure
```

### Вариант В: Файл конфигурации

```bash
./veil-client -config client.json
```

<br>

## 🌐 Настройка браузера

После подключения клиента настройте браузер:

**Firefox:**

1. Настройки → Параметры сети → Ручная настройка прокси
2. SOCKS: `127.0.0.1` — Порт: `1080`
3. **SOCKS v5**
4. Отметьте **«Отправлять DNS-запросы через прокси при использовании SOCKS v5»**

**Chrome:**

```bash
google-chrome --proxy-server="socks5://127.0.0.1:1080"
```

<br>

## 🔗 Ссылки подключения

Veil использует формат ссылок (как VLESS / Shadowsocks):

```
veil://СЕКРЕТ@ХОСТ:ПОРТ?transport=decoy&morph=http2_browsing
```

| Параметр | Значения | По умолчанию |
|:---|:---|:---|
| `transport` | `raw`, `tls`, `wss`, `decoy` | `tls` |
| `morph` | `http2_browsing`, `video_streaming` | `http2_browsing` |
| `cipher` | `chacha20-poly1305`, `aes-256-gcm` | `chacha20-poly1305` |
| `sni` | Любой домен | Имя хоста сервера |

<br>

## 🛠 Сборка из исходников

**Требования:** Go 1.21+

```bash
git clone https://github.com/CYHTm/veil-core.git
cd veil-core
go build -o bin/veil-server ./cmd/veil-server/
go build -o bin/veil-client ./cmd/veil-client/
go build -o bin/veil-app ./cmd/veil-app/
go test ./...
```

<br>

## 🤝 Участие в проекте

Нам нужна помощь:

- **Тестирование против реального DPI** — если у вас есть VPS в стране с цензурой
- **Профили трафика** — запись реального трафика браузера для новых морф-профилей
- **Аудит безопасности** — проверка криптографической реализации
- **Мобильные клиенты** — Android / iOS

См. [CONTRIBUTING.md](CONTRIBUTING.md).

<br>

## ⚠️ Дисклеймер

ПО предоставляется в образовательных и исследовательских целях. См. [DISCLAIMER.md](DISCLAIMER.md).

<br>

<div align="center">

<br>

[GitHub](https://github.com/CYHTm/veil-core) · [Releases](https://github.com/CYHTm/veil-core/releases) · [Issues](https://github.com/CYHTm/veil-core/issues)

MIT License · Made with purpose

<br>

</div>
