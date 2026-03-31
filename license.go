package license

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"
)

// apiResponse 服务端错误响应的通用结构
type apiResponse struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

// signedResponse 带签名的响应（对应服务端 SignedResponse）
type signedResponse struct {
	Data      json.RawMessage `json:"data"`
	Signature string          `json:"signature"`
}

// Config SDK 配置
type Config struct {
	LicenseCode string // 授权码
	ServerURL   string // 在线验证服务地址（如 https://license.example.com）
	LicenseFile string // 离线 License 文件路径
	PublicKey   string // RSA 公钥（PEM 格式），必须硬编码到产品二进制中

	TimeGuardFile string // 时间守卫文件路径，用于检测系统时间回调（默认与 LicenseFile 同目录）

	Fingerprint string // 机器指纹（为空时自动采集）
	Hostname    string // 主机名（为空时自动获取）
	OSInfo      string // 操作系统信息

	HTTPTimeout time.Duration // HTTP 请求超时，默认 10s
}

// VerifyResult 验证结果
type VerifyResult struct {
	Valid        bool       `json:"valid"`
	LicenseCode  string     `json:"license_code"`
	ProductCode  string     `json:"product_code"`
	LicenseType  string     `json:"license_type"`
	ExpiresAt    *time.Time `json:"expires_at"`
	MaxInstances int        `json:"max_instances"`
	Features     string     `json:"features"`
	Reason       string     `json:"reason"`
	Mode         string     `json:"mode"` // online / offline
}

// LicenseFile License 文件结构
type LicenseFile struct {
	License   LicensePayload `json:"license"`
	Signature string         `json:"signature"`
}

// LicensePayload License 文件中的授权数据
type LicensePayload struct {
	Code                string     `json:"code"`
	ProductCode         string     `json:"product_code"`
	CustomerName        string     `json:"customer_name"`
	LicenseType         string     `json:"license_type"`
	IssuedAt            time.Time  `json:"issued_at"`
	ExpiresAt           *time.Time `json:"expires_at"`
	MaxInstances        int        `json:"max_instances"`
	HardwareFingerprint string     `json:"hardware_fingerprint,omitempty"`
	Features            string     `json:"features,omitempty"`
}

// Client License SDK 客户端
type Client struct {
	config     Config
	httpClient *http.Client
	stopCh     chan struct{}
	watchdogCh chan struct{}
	mu         sync.Mutex
	running    bool
	watchdogOn bool
	onExpired  func() // 离线过期或时间异常时的回调
}

// NewClient 创建 License 客户端
func NewClient(config Config) *Client {
	if config.HTTPTimeout == 0 {
		config.HTTPTimeout = 10 * time.Second
	}
	if config.Fingerprint == "" {
		config.Fingerprint = CollectFingerprint()
	}
	if config.Hostname == "" {
		config.Hostname, _ = os.Hostname()
	}
	if config.TimeGuardFile == "" && config.LicenseFile != "" {
		config.TimeGuardFile = config.LicenseFile + ".tg"
	}

	return &Client{
		config: config,
		httpClient: &http.Client{
			Timeout: config.HTTPTimeout,
		},
		stopCh:     make(chan struct{}),
		watchdogCh: make(chan struct{}),
	}
}

// Verify 验证授权（混合模式：优先在线，失败降级离线）
func (c *Client) Verify() (*VerifyResult, error) {
	if c.config.ServerURL != "" {
		result, err := c.VerifyOnline()
		if err == nil {
			return result, nil
		}
	}

	if c.config.LicenseFile != "" && c.config.PublicKey != "" {
		return c.VerifyOffline()
	}

	return nil, fmt.Errorf("no verification method available: set ServerURL for online or LicenseFile+PublicKey for offline")
}

// VerifyOnline 在线验证
func (c *Client) VerifyOnline() (*VerifyResult, error) {
	reqBody := map[string]string{
		"license_code":         c.config.LicenseCode,
		"hardware_fingerprint": c.config.Fingerprint,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	resp, err := c.httpClient.Post(c.config.ServerURL+"/api/v1/license/verify", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp apiResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Message != "" {
			return nil, fmt.Errorf("verify failed: %s", errResp.Message)
		}
		return nil, fmt.Errorf("verify failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	dataBytes, err := c.verifyOnlineResponse(respBody)
	if err != nil {
		return nil, err
	}

	var result VerifyResult
	if err := json.Unmarshal(dataBytes, &result); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}
	result.Mode = "online"
	return &result, nil
}

// GetFingerprint 获取当前客户端的机器指纹
func (c *Client) GetFingerprint() string {
	return c.config.Fingerprint
}

// GetHostname 获取当前客户端的主机名
func (c *Client) GetHostname() string {
	return c.config.Hostname
}

// GetOSInfo 获取操作系统信息
func (c *Client) GetOSInfo() string {
	if c.config.OSInfo != "" {
		return c.config.OSInfo
	}
	return runtime.GOOS + "/" + runtime.GOARCH
}

// VerifyOffline 离线验证
func (c *Client) VerifyOffline() (*VerifyResult, error) {
	now := time.Now()

	if err := c.checkTimeGuard(now); err != nil {
		return &VerifyResult{Valid: false, Reason: err.Error(), Mode: "offline"}, nil
	}

	data, err := os.ReadFile(c.config.LicenseFile)
	if err != nil {
		return nil, fmt.Errorf("read license file: %w", err)
	}

	var licFile LicenseFile
	if err := json.Unmarshal(data, &licFile); err != nil {
		return nil, fmt.Errorf("parse license file: %w", err)
	}

	payloadBytes, err := json.Marshal(licFile.License)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}

	if err := verifySignature(payloadBytes, licFile.Signature, c.config.PublicKey); err != nil {
		return &VerifyResult{Valid: false, Reason: "签名验证失败: " + err.Error(), Mode: "offline"}, nil
	}

	result := &VerifyResult{
		LicenseCode:  licFile.License.Code,
		ProductCode:  licFile.License.ProductCode,
		LicenseType:  licFile.License.LicenseType,
		ExpiresAt:    licFile.License.ExpiresAt,
		MaxInstances: licFile.License.MaxInstances,
		Features:     licFile.License.Features,
		Mode:         "offline",
	}

	if licFile.License.LicenseType == "subscription" && licFile.License.ExpiresAt != nil {
		if licFile.License.ExpiresAt.Before(now) {
			result.Valid = false
			result.Reason = "授权已过期"
			c.updateTimeGuard(now)
			return result, nil
		}
	}

	if licFile.License.HardwareFingerprint != "" && licFile.License.HardwareFingerprint != c.config.Fingerprint {
		result.Valid = false
		result.Reason = "机器指纹不匹配"
		return result, nil
	}

	result.Valid = true
	c.updateTimeGuard(now)
	return result, nil
}

// ---------- TimeGuard: 时间回调检测 ----------

type timeGuardData struct {
	LastVerifyAt time.Time `json:"last_verify_at"`
}

func (c *Client) checkTimeGuard(now time.Time) error {
	if c.config.TimeGuardFile == "" {
		return nil
	}
	data, err := os.ReadFile(c.config.TimeGuardFile)
	if err != nil {
		return nil
	}
	var guard timeGuardData
	if err := json.Unmarshal(data, &guard); err != nil {
		return nil
	}
	if !guard.LastVerifyAt.IsZero() && now.Before(guard.LastVerifyAt.Add(-10*time.Minute)) {
		return fmt.Errorf("检测到系统时间异常（当前时间早于上次验证时间），请校正系统时钟")
	}
	return nil
}

func (c *Client) updateTimeGuard(now time.Time) {
	if c.config.TimeGuardFile == "" {
		return
	}
	guard := timeGuardData{LastVerifyAt: now}
	data, _ := json.Marshal(guard)
	_ = os.WriteFile(c.config.TimeGuardFile, data, 0644)
}

// ResetTimeGuard 重置时间守卫（激活/注销时调用）
func (c *Client) ResetTimeGuard() {
	if c.config.TimeGuardFile != "" {
		_ = os.Remove(c.config.TimeGuardFile)
	}
}

// Activate 在线激活
func (c *Client) Activate() error {
	if c.config.ServerURL == "" {
		return fmt.Errorf("ServerURL is required for activation")
	}

	reqBody := map[string]string{
		"license_code":         c.config.LicenseCode,
		"hardware_fingerprint": c.config.Fingerprint,
		"hostname":             c.config.Hostname,
		"ip_address":           getLocalIP(),
		"os_info":              c.GetOSInfo(),
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	resp, err := c.httpClient.Post(c.config.ServerURL+"/api/v1/license/activate", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return parseAPIError("activation failed", respBody)
	}

	if _, err := c.verifyOnlineResponse(respBody); err != nil {
		return err
	}
	return nil
}

// UpdateConfig 动态更新配置（用于切换授权码或 License 文件）
func (c *Client) UpdateConfig(config Config) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if config.LicenseCode != "" {
		c.config.LicenseCode = config.LicenseCode
	}
	if config.ServerURL != "" {
		c.config.ServerURL = config.ServerURL
	}
	if config.LicenseFile != "" {
		c.config.LicenseFile = config.LicenseFile
	}
}

// StartHeartbeat 启动后台心跳
func (c *Client) StartHeartbeat(interval time.Duration) {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return
	}
	c.running = true
	c.stopCh = make(chan struct{})
	c.mu.Unlock()

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_ = c.sendHeartbeat()
			case <-c.stopCh:
				return
			}
		}
	}()
}

// StopHeartbeat 停止心跳
func (c *Client) StopHeartbeat() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		close(c.stopCh)
		c.running = false
	}
}

// Deactivate 注销实例
func (c *Client) Deactivate() error {
	if c.config.ServerURL == "" {
		return fmt.Errorf("ServerURL is required for deactivation")
	}

	reqBody := map[string]string{
		"license_code":         c.config.LicenseCode,
		"hardware_fingerprint": c.config.Fingerprint,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	resp, err := c.httpClient.Post(c.config.ServerURL+"/api/v1/license/deactivate", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return parseAPIError("deactivation failed", respBody)
	}

	if _, err := c.verifyOnlineResponse(respBody); err != nil {
		return err
	}
	return nil
}

// StartOfflineWatchdog 启动离线授权定时检查（检查过期 + 时间回调）
// onExpired 回调在授权失效时触发（过期或时间异常），传 nil 则不回调
func (c *Client) StartOfflineWatchdog(interval time.Duration, onExpired func()) {
	c.mu.Lock()
	if c.watchdogOn {
		c.mu.Unlock()
		return
	}
	c.watchdogOn = true
	c.onExpired = onExpired
	c.watchdogCh = make(chan struct{})
	c.mu.Unlock()

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				result, err := c.VerifyOffline()
				if err != nil || !result.Valid {
					if c.onExpired != nil {
						c.onExpired()
					}
				}
			case <-c.watchdogCh:
				return
			}
		}
	}()
}

// StopOfflineWatchdog 停止离线定时检查
func (c *Client) StopOfflineWatchdog() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.watchdogOn {
		close(c.watchdogCh)
		c.watchdogOn = false
	}
}

// Shutdown 优雅关闭（停止心跳 + 停止 watchdog + 注销实例）
func (c *Client) Shutdown(ctx context.Context) error {
	c.StopHeartbeat()
	c.StopOfflineWatchdog()
	return c.Deactivate()
}

func (c *Client) sendHeartbeat() error {
	if c.config.ServerURL == "" {
		return nil
	}

	reqBody := map[string]string{
		"license_code":         c.config.LicenseCode,
		"hardware_fingerprint": c.config.Fingerprint,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Post(c.config.ServerURL+"/api/v1/license/heartbeat", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return parseAPIError("heartbeat failed", respBody)
	}

	if _, err := c.verifyOnlineResponse(respBody); err != nil {
		return err
	}
	return nil
}

func parseAPIError(prefix string, body []byte) error {
	var errResp apiResponse
	if err := json.Unmarshal(body, &errResp); err == nil && errResp.Message != "" {
		return fmt.Errorf("%s: %s", prefix, errResp.Message)
	}
	return fmt.Errorf("%s: %s", prefix, string(body))
}

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return ""
}

// verifyOnlineResponse 验证在线响应的签名，返回 data 部分的原始 JSON
func (c *Client) verifyOnlineResponse(respBody []byte) (json.RawMessage, error) {
	if c.config.PublicKey == "" {
		return nil, fmt.Errorf("PublicKey 未配置，无法验证服务端响应签名")
	}

	var signed signedResponse
	if err := json.Unmarshal(respBody, &signed); err != nil {
		return nil, fmt.Errorf("解析签名响应失败: %w", err)
	}

	if signed.Signature == "" {
		return nil, fmt.Errorf("服务端响应缺少签名，可能为伪造服务")
	}

	if err := verifySignature(signed.Data, signed.Signature, c.config.PublicKey); err != nil {
		return nil, fmt.Errorf("响应签名验证失败，数据可能被篡改: %w", err)
	}

	return signed.Data, nil
}

func verifySignature(data []byte, signatureBase64, publicKeyPEM string) error {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return fmt.Errorf("无法解析PEM格式公钥")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("解析公钥失败: %w", err)
	}

	publicKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("不是RSA公钥")
	}

	signature, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return fmt.Errorf("解码签名失败: %w", err)
	}

	hash := sha256.Sum256(data)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], signature)
}
