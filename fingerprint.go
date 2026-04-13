package license

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

// CollectFingerprint 采集机器指纹，返回 64 字符的 hex 字符串。
//
// 只使用跨重启/Docker 重启后仍然稳定的维度：
//   - OS + Arch（永远稳定）
//   - Machine ID（/etc/machine-id 或注册表 MachineGuid，物理机和 VM 上稳定，
//     Docker 中建议挂载宿主机 /etc/machine-id 为只读卷）
//   - CPU 型号/ID（同一台物理机上不变）
//
// 已排除的不稳定因子：
//   - MAC 地址：Docker 每次启动随机分配虚拟网卡 MAC
//   - Hostname：Docker 默认 hostname 是随机容器 ID
//   - Disk ID：Docker 容器中通常无法采集
func CollectFingerprint() string {
	parts := collectFingerprintParts()
	data := strings.Join(parts, "|")
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)
}

func collectFingerprintParts() []string {
	var parts []string

	parts = append(parts, "os:"+runtime.GOOS, "arch:"+runtime.GOARCH)

	if machineID := getMachineIdentifier(); machineID != "" {
		parts = append(parts, "machine:"+machineID)
	}
	if cpuID := getCPUIdentifier(); cpuID != "" {
		parts = append(parts, "cpu:"+cpuID)
	}

	var normalized []string
	for _, p := range parts {
		v := strings.ToLower(strings.TrimSpace(p))
		v = strings.Join(strings.Fields(v), " ")
		if v != "" {
			normalized = append(normalized, v)
		}
	}
	sort.Strings(normalized)
	if len(normalized) == 0 {
		return []string{"fallback:unknown"}
	}
	return normalized
}

func getMachineIdentifier() string {
	switch runtime.GOOS {
	case "windows":
		return getWindowsMachineGUID()
	case "linux":
		return getLinuxMachineID()
	case "darwin":
		return getDarwinPlatformUUID()
	default:
		return ""
	}
}

func getCPUIdentifier() string {
	switch runtime.GOOS {
	case "windows":
		return getWindowsCPUIdentifier()
	case "linux":
		return getLinuxCPUIdentifier()
	case "darwin":
		return getDarwinCPUIdentifier()
	default:
		return ""
	}
}

func getWindowsMachineGUID() string {
	out := runCommand(3*time.Second, "reg", "query", `HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid")
	for _, line := range splitNonEmptyLines(out) {
		if !strings.Contains(strings.ToLower(line), "machineguid") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			return fields[len(fields)-1]
		}
	}
	return ""
}

func getLinuxMachineID() string {
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(path); err == nil {
			if v := strings.TrimSpace(string(b)); v != "" {
				return v
			}
		}
	}
	return ""
}

func getDarwinPlatformUUID() string {
	out := runCommand(3*time.Second, "ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	return regexFindFirst(out, `"IOPlatformUUID"\s*=\s*"([^"]+)"`)
}

func getWindowsCPUIdentifier() string {
	out := runCommand(3*time.Second, "wmic", "cpu", "get", "ProcessorId")
	id := firstUsefulLine(out, "processorid")
	if id != "" {
		return id
	}
	return runCommand(4*time.Second, "powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty ProcessorId)")
}

func getLinuxCPUIdentifier() string {
	b, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return ""
	}

	var values []string
	keys := []string{"serial", "vendor_id", "cpu family", "model", "stepping", "model name"}
	lowerData := strings.ToLower(string(b))
	for _, key := range keys {
		if val := extractKVByKey(lowerData, key); val != "" {
			values = append(values, key+"="+val)
		}
	}
	return strings.Join(values, "|")
}

func getDarwinCPUIdentifier() string {
	brand := runCommand(2*time.Second, "sysctl", "-n", "machdep.cpu.brand_string")
	signature := runCommand(2*time.Second, "sysctl", "-n", "machdep.cpu.signature")
	var values []string
	if brand != "" {
		values = append(values, "brand="+brand)
	}
	if signature != "" {
		values = append(values, "signature="+signature)
	}
	return strings.Join(values, "|")
}

func runCommand(timeout time.Duration, name string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func splitNonEmptyLines(s string) []string {
	lines := strings.Split(s, "\n")
	var result []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

func firstUsefulLine(output string, skipContains string) string {
	for _, line := range splitNonEmptyLines(output) {
		normalized := strings.ToLower(strings.TrimSpace(line))
		if skipContains != "" && strings.Contains(normalized, strings.ToLower(skipContains)) {
			continue
		}
		return line
	}
	return ""
}

func regexFindFirst(s string, pattern string) string {
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(s)
	if len(matches) < 2 {
		return ""
	}
	return strings.TrimSpace(matches[1])
}

func extractKVByKey(content string, key string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, key) || !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		return strings.TrimSpace(parts[1])
	}
	return ""
}
