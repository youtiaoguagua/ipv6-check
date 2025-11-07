package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/joho/godotenv"
)

// 配置参数结构
type Config struct {
	Host         string
	Port         string
	Interval     int
	MaxFailures  int
	RebootURL    string
	MaxCalls     int
	TimeWindow   int
	EnableReboot bool
	LogLevel     string
	WebhookURL   string
	WebhookTitle string
}

// 加载配置
func loadConfig() Config {
	// 尝试加载 .env 文件（如果存在）
	godotenv.Load()

	cfg := Config{
		Host:         getEnvOrDefault("HOST", "ipv6.baidu.com"),
		Port:         getEnvOrDefault("PORT", "80"),
		Interval:     getEnvAsInt("INTERVAL", 30),
		MaxFailures:  getEnvAsInt("MAX_FAILURES", 3),
		RebootURL:    getEnvOrDefault("REBOOT_URL", "http://example.com/cgi-bin/example?token=example"),
		MaxCalls:     getEnvAsInt("MAX_CALLS", 2),
		TimeWindow:   getEnvAsInt("TIME_WINDOW", 60),
		EnableReboot: getEnvAsBool("ENABLE_REBOOT", true),
		LogLevel:     getEnvOrDefault("LOG_LEVEL", "INFO"),
		WebhookURL:   getEnvOrDefault("WEBHOOK_URL", ""),
		WebhookTitle: getEnvOrDefault("WEBHOOK_TITLE", "IPv6检测通知"),
	}

	return cfg
}

// 获取环境变量或默认值
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// 获取环境变量并转换为整数
func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// 获取环境变量并转换为布尔值
func getEnvAsBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

// 调用记录结构
type callTracker struct {
	calls []time.Time
	mutex sync.Mutex
}

// 添加一次调用
func (ct *callTracker) addCall() {
	ct.mutex.Lock()
	defer ct.mutex.Unlock()
	ct.calls = append(ct.calls, time.Now())
}

// 清理过期的调用记录
func (ct *callTracker) cleanup(now time.Time, timeWindow int) {
	ct.mutex.Lock()
	defer ct.mutex.Unlock()
	cutoff := now.Add(-time.Duration(timeWindow) * time.Minute)
	var validCalls []time.Time
	for _, call := range ct.calls {
		if call.After(cutoff) {
			validCalls = append(validCalls, call)
		}
	}
	ct.calls = validCalls
}

// 获取在时间窗口内的调用次数
func (ct *callTracker) getCallCount(now time.Time) int {
	ct.mutex.Lock()
	defer ct.mutex.Unlock()
	return len(ct.calls)
}

// 检测TCP连接
func testTCPConnect(host, port string, logger *slog.Logger) (bool, net.Addr) {
	addr := net.JoinHostPort(host, port)
	logger.Info("尝试连接 TCP", "target", addr, "protocol", "IPv6 only")

	// 使用 DialContext 允许设置超时
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 明确指定 "tcp6" 网络类型，只尝试 IPv6 连接
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp6", addr)
	if err != nil {
		logger.Error("连接失败", "target", addr, "error", err)
		return false, nil
	}
	defer conn.Close()

	logger.Info("连接成功", "target", addr, "local", conn.LocalAddr(), "remote", conn.RemoteAddr())
	return true, conn.RemoteAddr()
}

// 触发重启
func triggerReboot(url string, logger *slog.Logger) {
	logger.Info("触发重启操作", "url", url)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		logger.Error("重启请求失败", "url", url, "error", err)
		return
	}
	defer resp.Body.Close()

	logger.Info("重启请求成功发送", "url", url, "status", resp.StatusCode)
}

// 发送 webhook 通知
func sendWebhook(url, title, content string, logger *slog.Logger) bool {
	if url == "" {
		logger.Debug("Webhook URL 未配置，跳过通知")
		return true
	}

	payload := map[string]string{
		"title":   title,
		"content": content,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		logger.Error("序列化 webhook 数据失败", "error", err)
		return false
	}

	logger.Info("发送 webhook 通知", "url", url, "title", title)

	// 或缺
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
	}

	resp, err := client.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		logger.Error("Webhook 请求失败", "url", url, "error", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		logger.Info("Webhook 通知发送成功", "url", url, "status", resp.StatusCode)
		return true
	} else {
		logger.Warn("Webhook 通知发送失败", "url", url, "status", resp.StatusCode)
		return false
	}
}

// 检查是否可以调用重启
func (ct *callTracker) canCallReboot(cfg Config) bool {
	now := time.Now()
	ct.cleanup(now, cfg.TimeWindow)
	return ct.getCallCount(now) < cfg.MaxCalls
}

func main() {
	// 加载配置
	cfg := loadConfig()

	// 配置日志级别
	level := slog.LevelInfo
	switch cfg.LogLevel {
	case "DEBUG":
		level = slog.LevelDebug
	case "INFO":
		level = slog.LevelInfo
	case "WARN":
		level = slog.LevelWarn
	case "ERROR":
		level = slog.LevelError
	}

	// 配置slog（使用结构化日志，输出到标准输出）
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))

	// 输出配置信息
	logger.Info("=== IPv6 连接检测与自动重启工具 ===")
	logger.Info("配置信息 - 检测目标", "value", fmt.Sprintf("%s:%s", cfg.Host, cfg.Port))
	logger.Info("配置信息 - 检测间隔", "value", fmt.Sprintf("%d 秒", cfg.Interval))
	logger.Info("配置信息 - 最大失败次数", "value", cfg.MaxFailures)
	logger.Info("配置信息 - 重启URL", "value", cfg.RebootURL)
	logger.Info("配置信息 - 每小时最大重启次数", "value", cfg.MaxCalls)
	logger.Info("配置信息 - 时间窗口", "value", fmt.Sprintf("%d 分钟", cfg.TimeWindow))
	logger.Info("配置信息 - 自动重启", "value", cfg.EnableReboot)
	logger.Info("配置信息 - 日志级别", "value", cfg.LogLevel)
	logger.Info("配置信息 - Webhook URL", "value", cfg.WebhookURL)
	logger.Info("配置信息 - Webhook Title", "value", cfg.WebhookTitle)

	// 初始化调用跟踪器
	tracker := &callTracker{calls: make([]time.Time, 0)}

	failureCount := 0
	ticker := time.NewTicker(time.Duration(cfg.Interval) * time.Second)

	for {
		select {
		case <-ticker.C:
			// 执行IPv6检测
			success, remoteAddr := testTCPConnect(cfg.Host, cfg.Port, logger)

			if success {
				if failureCount > 0 {
					logger.Info("连接恢复，失败计数重置", "之前失败次数", failureCount)
					// 发送成功通知
					title := fmt.Sprintf("✅ %s 连接成功", cfg.Host)
					content := fmt.Sprintf("域名 %s 连接已恢复，远程地址: %s", cfg.Host, remoteAddr)
					sendWebhook(cfg.WebhookURL, title, content, logger)
				}
				failureCount = 0
			} else {
				failureCount++
				logger.Warn("连接失败", "连续失败次数", fmt.Sprintf("%d / %d", failureCount, cfg.MaxFailures))

				// 检查是否达到最大失败次数
				if failureCount >= cfg.MaxFailures {
					if !cfg.EnableReboot {
						logger.Warn("达到最大失败次数，但自动重启功能已禁用", "max-failures", cfg.MaxFailures)
						failureCount = 0 // 重置失败计数
					} else if !tracker.canCallReboot(cfg) {
						logger.Warn("达到最大失败次数，但重启调用次数已达上限",
							"max-failures", cfg.MaxFailures,
							"max-calls", cfg.MaxCalls,
							"time-window", fmt.Sprintf("%d分钟", cfg.TimeWindow))
						failureCount = 0 // 重置失败计数
					} else {
						logger.Error("连续失败次数达到上限，触发重启", "连续失败次数", cfg.MaxFailures)
						triggerReboot(cfg.RebootURL, logger)
						tracker.addCall()
						failureCount = 0 // 重置失败计数

						// 发送重启通知
						title := fmt.Sprintf("%s 自动重启已触发", cfg.Host)
						content := fmt.Sprintf("检测到 %s 连续 %d 次连接失败，已触发自动重启。重启URL: %s", cfg.Host, cfg.MaxFailures, cfg.RebootURL)
						sendWebhook(cfg.WebhookURL, title, content, logger)

						if tracker.getCallCount(time.Now()) >= cfg.MaxCalls {
							logger.Warn("已达到每小时最大重启次数", "max-calls", cfg.MaxCalls)
						}
					}
				}
			}

			// 显示当前窗口内的调用次数
			if cfg.EnableReboot {
				logger.Info("重启调用次数统计",
					"当前次数", tracker.getCallCount(time.Now()),
					"上限", cfg.MaxCalls,
					"时间窗口", fmt.Sprintf("过去 %d 分钟", cfg.TimeWindow))
			}
		}
	}
}
