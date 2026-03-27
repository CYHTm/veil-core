// Package api — sysproxy.go manages system proxy settings.
// On Linux, sets GNOME/KDE proxy and also provides env vars.
package api

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// SetSystemProxy configures the OS to use our SOCKS5 proxy.
func SetSystemProxy(socksAddr string) error {
	parts := strings.SplitN(socksAddr, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid socks addr: %s", socksAddr)
	}
	host, port := parts[0], parts[1]

	switch runtime.GOOS {
	case "linux":
		return setLinuxProxy(host, port)
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// UnsetSystemProxy removes the system proxy settings.
func UnsetSystemProxy() error {
	switch runtime.GOOS {
	case "linux":
		return unsetLinuxProxy()
	default:
		return nil
	}
}

func setLinuxProxy(host, port string) error {
	// Try GNOME (gsettings)
	if _, err := exec.LookPath("gsettings"); err == nil {
		exec.Command("gsettings", "set", "org.gnome.system.proxy", "mode", "manual").Run()
		exec.Command("gsettings", "set", "org.gnome.system.proxy.socks", "host", host).Run()
		exec.Command("gsettings", "set", "org.gnome.system.proxy.socks", "port", port).Run()
		return nil
	}

	// Try KDE
	if _, err := exec.LookPath("kwriteconfig5"); err == nil {
		exec.Command("kwriteconfig5", "--file", "kioslaverc",
			"--group", "Proxy Settings", "--key", "ProxyType", "1").Run()
		exec.Command("kwriteconfig5", "--file", "kioslaverc",
			"--group", "Proxy Settings", "--key", "socksProxy",
			fmt.Sprintf("socks://%s:%s", host, port)).Run()
		return nil
	}

	// Fallback: just inform user
	return fmt.Errorf("не удалось автоматически — настрой прокси вручную: SOCKS5 %s:%s", host, port)
}

func unsetLinuxProxy() error {
	if _, err := exec.LookPath("gsettings"); err == nil {
		exec.Command("gsettings", "set", "org.gnome.system.proxy", "mode", "none").Run()
		return nil
	}
	if _, err := exec.LookPath("kwriteconfig5"); err == nil {
		exec.Command("kwriteconfig5", "--file", "kioslaverc",
			"--group", "Proxy Settings", "--key", "ProxyType", "0").Run()
		return nil
	}
	return nil
}
