package api

import (
	"math/rand"
	"time"
)

// DecoySite represents one possible decoy website to show.
type DecoySite struct {
	Name       string
	ServerName string // HTTP Server header
	HTML       string
	NotFound   string
}

// DecoySitePool manages multiple decoy identities.
// Each new visitor sees a different site, making it harder
// for censors to fingerprint by HTML content.
type DecoySitePool struct {
	sites []DecoySite
	rng   *rand.Rand
}

// NewDecoySitePool creates a pool with built-in sites.
func NewDecoySitePool() *DecoySitePool {
	return &DecoySitePool{
		sites: builtinSites,
		rng:   rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Random returns a random decoy site.
func (p *DecoySitePool) Random() DecoySite {
	return p.sites[p.rng.Intn(len(p.sites))]
}

// AddSite adds a custom decoy site.
func (p *DecoySitePool) AddSite(site DecoySite) {
	p.sites = append(p.sites, site)
}

var builtinSites = []DecoySite{
	{
		Name:       "CloudMatrix",
		ServerName: "nginx/1.24.0",
		HTML: `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CloudMatrix — Enterprise Cloud Solutions</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,sans-serif;color:#1f2937}.nav{background:#fff;padding:14px 40px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #e5e7eb}.nav .logo{font-size:18px;font-weight:700;color:#2563eb}.hero{background:linear-gradient(135deg,#1e3a8a,#3b82f6);color:#fff;padding:80px 40px;text-align:center}.hero h1{font-size:36px;margin-bottom:16px}.hero p{font-size:16px;opacity:.9;max-width:560px;margin:0 auto}.features{padding:48px 40px;display:grid;grid-template-columns:repeat(3,1fr);gap:24px;max-width:900px;margin:0 auto}.card{border:1px solid #e5e7eb;border-radius:12px;padding:20px}.card h3{font-size:15px;margin-bottom:6px}.card p{font-size:13px;color:#6b7280}.footer{padding:20px;text-align:center;color:#9ca3af;font-size:12px}</style></head><body><nav class="nav"><div class="logo">CloudMatrix</div></nav><div class="hero"><h1>Infrastructure That Scales</h1><p>Enterprise-grade cloud platform with 99.99% uptime.</p></div><div class="features"><div class="card"><h3>Auto Scaling</h3><p>Scale resources based on demand.</p></div><div class="card"><h3>Security</h3><p>SOC 2 Type II certified.</p></div><div class="card"><h3>Global CDN</h3><p>42 edge locations worldwide.</p></div></div><footer class="footer">© 2024 CloudMatrix Inc.</footer></body></html>`,
	},
	{
		Name:       "NovaDocs",
		ServerName: "Apache/2.4.58",
		HTML: `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>NovaDocs — Document Management</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',sans-serif;color:#333;background:#f7f7f8}.nav{background:#fff;padding:12px 32px;border-bottom:1px solid #ddd;display:flex;align-items:center;gap:12px}.nav b{font-size:17px;color:#5b21b6}.main{max-width:800px;margin:40px auto;padding:0 20px}.main h1{font-size:28px;margin-bottom:8px}.main p{color:#666;margin-bottom:24px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.box{background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:16px}.box h3{font-size:14px;margin-bottom:4px;color:#5b21b6}.box p{font-size:12px;color:#888}.footer{text-align:center;padding:24px;color:#aaa;font-size:11px}</style></head><body><nav class="nav"><b>NovaDocs</b></nav><div class="main"><h1>Smart Document Management</h1><p>Organize, collaborate, and secure your documents in the cloud.</p><div class="grid"><div class="box"><h3>Version Control</h3><p>Track every change with full history.</p></div><div class="box"><h3>Team Sharing</h3><p>Real-time collaboration with your team.</p></div><div class="box"><h3>Encryption</h3><p>End-to-end encrypted storage.</p></div><div class="box"><h3>API Access</h3><p>RESTful API for integrations.</p></div></div></div><footer class="footer">© 2024 NovaDocs Ltd.</footer></body></html>`,
	},
	{
		Name:       "PulseMetrics",
		ServerName: "cloudflare",
		HTML: `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PulseMetrics — Analytics Platform</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,sans-serif;background:#0f172a;color:#e2e8f0}.nav{padding:16px 32px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #1e293b}.nav b{color:#38bdf8;font-size:17px}.hero{padding:64px 32px;text-align:center}.hero h1{font-size:32px;margin-bottom:12px;background:linear-gradient(90deg,#38bdf8,#818cf8);-webkit-background-clip:text;-webkit-text-fill-color:transparent}.hero p{color:#94a3b8;max-width:500px;margin:0 auto}.stats{display:flex;justify-content:center;gap:48px;padding:40px}.stat b{display:block;font-size:28px;color:#38bdf8}.stat span{font-size:12px;color:#64748b}.footer{text-align:center;padding:20px;color:#475569;font-size:11px}</style></head><body><nav class="nav"><b>PulseMetrics</b></nav><div class="hero"><h1>Real-Time Analytics</h1><p>Understand your users with AI-powered insights and dashboards.</p></div><div class="stats"><div class="stat"><b>2.4B</b><span>Events/day</span></div><div class="stat"><b>50ms</b><span>Query time</span></div><div class="stat"><b>99.9%</b><span>Uptime</span></div></div><footer class="footer">© 2024 PulseMetrics Inc.</footer></body></html>`,
	},
}
