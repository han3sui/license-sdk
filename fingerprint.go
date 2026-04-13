package license

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

// FingerprintDimensions 各维度的独立 hash，用于模糊匹配。
// 每个维度单独计算 hash，比对时只要达到阈值数量的维度匹配即可认定为同一台机器。
type FingerprintDimensions struct {
	OS      string `json:"os"`
	MAC     string `json:"mac,omitempty"`
	Machine string `json:"machine,omitempty"`
	CPU     string `json:"cpu,omitempty"`
	Disk    string `json:"disk,omitempty"`
}

const defaultMatchThreshold = 3

// CollectFingerprint 采集机器指纹（返回 JSON 编码的多维度指纹）
func CollectFingerprint() string {
	dims := CollectFingerprintDimensions()
	b, _ := json.Marshal(dims)
	return string(b)
}

// CollectFingerprintDimensions 采集各维度的独立 hash
func CollectFingerprintDimensions() FingerprintDimensions {
	dims := FingerprintDimensions{
		OS: hashValue("os:" + runtime.GOOS + "|arch:" + runtime.GOARCH),
	}

	if macs := getMACAddresses(); len(macs) > 0 {
		dims.MAC = hashValue("mac:" + strings.Join(macs, ","))
	}
	if machineID := getMachineIdentifier(); machineID != "" {
		dims.Machine = hashValue("machine:" + machineID)
	}
	if cpuID := getCPUIdentifier(); cpuID != "" {
		dims.CPU = hashValue("cpu:" + cpuID)
	}
	if diskID := getDiskIdentifier(); diskID != "" {
		dims.Disk = hashValue("disk:" + diskID)
	}

	return dims
}

// MatchFingerprint 模糊匹配两个指纹，至少 threshold 个非空维度匹配即返回 true。
// threshold <= 0 时使用默认阈值 3。
func MatchFingerprint(stored, current string, threshold int) bool {
	if threshold <= 0 {
		threshold = defaultMatchThreshold
	}

	if stored == current {
		return true
	}

	storedDims, errS := parseDimensions(stored)
	currentDims, errC := parseDimensions(current)
	if errS != nil || errC != nil {
		return stored == current
	}

	matched := 0
	total := 0
	for _, pair := range []struct{ a, b string }{
		{storedDims.OS, currentDims.OS},
		{storedDims.MAC, currentDims.MAC},
		{storedDims.Machine, currentDims.Machine},
		{storedDims.CPU, currentDims.CPU},
		{storedDims.Disk, currentDims.Disk},
	} {
		if pair.a == "" || pair.b == "" {
			continue
		}
		total++
		if pair.a == pair.b {
			matched++
		}
	}

	if total < threshold {
		return matched == total && total > 0
	}
	return matched >= threshold
}

func parseDimensions(s string) (FingerprintDimensions, error) {
	var dims FingerprintDimensions
	err := json.Unmarshal([]byte(s), &dims)
	return dims, err
}

func hashValue(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h[:16])
}

// virtualIfacePrefixes 需要排除的虚拟网卡名称前缀
var virtualIfacePrefixes = []string{
	"veth", "docker", "br-", "virbr", "vbox", "vmnet",
	"flannel", "cni", "calico", "tunl", "wg",
}

func getMACAddresses() []string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var macs []string
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(iface.HardwareAddr) == 0 {
			continue
		}
		if isVirtualInterface(iface.Name) {
			continue
		}
		mac := iface.HardwareAddr.String()
		if mac != "" {
			macs = append(macs, mac)
		}
	}

	sort.Strings(macs)
	return macs
}

func isVirtualInterface(name string) bool {
	lower := strings.ToLower(name)
	for _, prefix := range virtualIfacePrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
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

func getDiskIdentifier() string {
	switch runtime.GOOS {
	case "windows":
		return getWindowsDiskIdentifier()
	case "linux":
		return getLinuxDiskIdentifier()
	case "darwin":
		return getDarwinDiskIdentifier()
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

func getWindowsDiskIdentifier() string {
	out := runCommand(3*time.Second, "wmic", "diskdrive", "get", "SerialNumber")
	id := firstUsefulLine(out, "serialnumber")
	if id != "" {
		return id
	}
	return runCommand(4*time.Second, "powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_DiskDrive | Select-Object -First 1 -ExpandProperty SerialNumber)")
}

func getLinuxDiskIdentifier() string {
	out := runCommand(2*time.Second, "lsblk", "-dn", "-o", "SERIAL")
	if id := firstUsefulLine(out, "serial"); id != "" {
		return id
	}

	entries, err := os.ReadDir("/dev/disk/by-id")
	if err != nil {
		return ""
	}
	var ids []string
	for _, e := range entries {
		name := e.Name()
		if strings.Contains(name, "-part") {
			continue
		}
		if strings.HasPrefix(name, "wwn-") || strings.HasPrefix(name, "nvme-") || strings.HasPrefix(name, "ata-") {
			ids = append(ids, name)
		}
	}
	sort.Strings(ids)
	if len(ids) == 0 {
		return ""
	}
	return ids[0]
}

func getDarwinDiskIdentifier() string {
	out := runCommand(3*time.Second, "diskutil", "info", "/")
	if uuid := regexFindFirst(out, `(?mi)Disk / Partition UUID:\s*([^\r\n]+)`); uuid != "" {
		return uuid
	}
	return regexFindFirst(out, `(?mi)Volume UUID:\s*([^\r\n]+)`)
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
