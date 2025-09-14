package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

// PerformanceMetrics holds real-time performance data
type PerformanceMetrics struct {
	Timestamp       time.Time `json:"timestamp"`
	ResponseTime    int64     `json:"response_time_ms"`
	StatusCode      int       `json:"status_code"`
	Success         bool      `json:"success"`
	ErrorMessage    string    `json:"error_message,omitempty"`
	ThroughputBPS   float64   `json:"throughput_bps"`
	MemoryUsageMB   float64   `json:"memory_usage_mb"`
	GoroutineCount  int       `json:"goroutine_count"`
	HeapSizeMB      float64   `json:"heap_size_mb"`
}

// SystemHealth represents overall system health status
type SystemHealth struct {
	Status           string    `json:"status"`
	Timestamp        time.Time `json:"timestamp"`
	AvgResponseTime  float64   `json:"avg_response_time_ms"`
	SuccessRate      float64   `json:"success_rate_percent"`
	RequestsPerMin   int       `json:"requests_per_minute"`
	ErrorCount       int       `json:"error_count"`
	MemoryUsageMB    float64   `json:"memory_usage_mb"`
	UptimeSeconds    int64     `json:"uptime_seconds"`
	HealthScore      int       `json:"health_score"`
}

// PerformanceMonitor manages continuous performance monitoring
type PerformanceMonitor struct {
	targetURL       string
	interval        time.Duration
	client          *http.Client
	metrics         []PerformanceMetrics
	startTime       time.Time
	totalRequests   int
	successCount    int
	errorCount      int
	totalResponseTime int64
	maxMetrics      int
}

// NewPerformanceMonitor creates a new performance monitor
func NewPerformanceMonitor(targetURL string, interval time.Duration) *PerformanceMonitor {
	return &PerformanceMonitor{
		targetURL: targetURL,
		interval:  interval,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		metrics:    make([]PerformanceMetrics, 0),
		startTime:  time.Now(),
		maxMetrics: 1000, // Keep last 1000 measurements
	}
}

// Start begins continuous monitoring
func (pm *PerformanceMonitor) Start() {
	fmt.Printf("🔍 Performance Monitor Started\n")
	fmt.Printf("Target: %s\n", pm.targetURL)
	fmt.Printf("Interval: %v\n", pm.interval)
	fmt.Printf("Press Ctrl+C to stop monitoring\n\n")
	
	ticker := time.NewTicker(pm.interval)
	defer ticker.Stop()
	
	// Display header
	pm.printHeader()
	
	for {
		select {
		case <-ticker.C:
			metric := pm.measurePerformance()
			pm.addMetric(metric)
			pm.displayRealTimeMetrics(metric)
			
			// Display health summary every 10 measurements
			if pm.totalRequests%10 == 0 {
				pm.displayHealthSummary()
			}
		}
	}
}

// measurePerformance performs a single performance measurement
func (pm *PerformanceMonitor) measurePerformance() PerformanceMetrics {
	start := time.Now()
	
	resp, err := pm.client.Get(pm.targetURL)
	duration := time.Since(start)
	
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	metric := PerformanceMetrics{
		Timestamp:      start,
		ResponseTime:   duration.Milliseconds(),
		MemoryUsageMB:  float64(m.Sys) / 1024 / 1024,
		GoroutineCount: runtime.NumGoroutine(),
		HeapSizeMB:     float64(m.HeapAlloc) / 1024 / 1024,
	}
	
	pm.totalRequests++
	
	if err != nil {
		metric.Success = false
		metric.ErrorMessage = err.Error()
		pm.errorCount++
	} else {
		defer resp.Body.Close()
		
		metric.StatusCode = resp.StatusCode
		metric.Success = resp.StatusCode >= 200 && resp.StatusCode < 400
		
		if metric.Success {
			pm.successCount++
		} else {
			pm.errorCount++
		}
		
		// Measure response size for throughput calculation
		body, _ := io.ReadAll(resp.Body)
		responseSize := len(body)
		metric.ThroughputBPS = float64(responseSize) / duration.Seconds()
	}
	
	pm.totalResponseTime += metric.ResponseTime
	
	return metric
}

// addMetric adds a metric to the collection with size limit
func (pm *PerformanceMonitor) addMetric(metric PerformanceMetrics) {
	pm.metrics = append(pm.metrics, metric)
	
	// Keep only the last maxMetrics measurements
	if len(pm.metrics) > pm.maxMetrics {
		pm.metrics = pm.metrics[1:]
	}
}

// printHeader displays the monitoring table header
func (pm *PerformanceMonitor) printHeader() {
	fmt.Printf("%s\n", strings.Repeat("=", 100))
	fmt.Printf("%-19s %-8s %-6s %-10s %-12s %-8s %-10s %-12s\n",
		"TIMESTAMP", "STATUS", "RT(ms)", "THROUGHPUT", "SUCCESS_RATE", "ERRORS", "MEMORY(MB)", "GOROUTINES")
	fmt.Printf("%s\n", strings.Repeat("-", 100))
}

// displayRealTimeMetrics shows current measurement in table format
func (pm *PerformanceMonitor) displayRealTimeMetrics(metric PerformanceMetrics) {
	status := "✅"
	if !metric.Success {
		status = "❌"
	}
	
	successRate := float64(pm.successCount) / float64(pm.totalRequests) * 100
	throughputKB := metric.ThroughputBPS / 1024
	
	fmt.Printf("%-19s %-8s %-6d %-10.1f %-12.1f%% %-8d %-10.1f %-12d\n",
		metric.Timestamp.Format("15:04:05.000"),
		status,
		metric.ResponseTime,
		throughputKB,
		successRate,
		pm.errorCount,
		metric.MemoryUsageMB,
		metric.GoroutineCount)
}

// displayHealthSummary shows periodic health summary
func (pm *PerformanceMonitor) displayHealthSummary() {
	health := pm.calculateSystemHealth()
	
	fmt.Printf("\n%s\n", strings.Repeat("=", 80))
	fmt.Printf("📊 SYSTEM HEALTH SUMMARY\n")
	fmt.Printf("%s\n", strings.Repeat("=", 80))
	fmt.Printf("Status: %s | Health Score: %d/100\n", health.Status, health.HealthScore)
	fmt.Printf("Avg Response Time: %.1fms | Success Rate: %.1f%%\n", 
		health.AvgResponseTime, health.SuccessRate)
	fmt.Printf("Requests/Min: %d | Total Errors: %d\n", 
		health.RequestsPerMin, health.ErrorCount)
	fmt.Printf("Memory Usage: %.1fMB | Uptime: %ds\n", 
		health.MemoryUsageMB, health.UptimeSeconds)
	fmt.Printf("%s\n\n", strings.Repeat("=", 80))
	
	// Save health data
	pm.saveHealthData(health)
}

// calculateSystemHealth computes overall system health metrics
func (pm *PerformanceMonitor) calculateSystemHealth() SystemHealth {
	uptime := time.Since(pm.startTime)
	avgResponseTime := float64(pm.totalResponseTime) / float64(pm.totalRequests)
	successRate := float64(pm.successCount) / float64(pm.totalRequests) * 100
	requestsPerMin := int(float64(pm.totalRequests) / uptime.Minutes())
	
	// Calculate health score (0-100)
	healthScore := pm.calculateHealthScore(avgResponseTime, successRate)
	
	// Determine status
	status := "HEALTHY"
	if healthScore < 70 {
		status = "DEGRADED"
	}
	if healthScore < 50 {
		status = "UNHEALTHY"
	}
	
	var memUsage float64
	if len(pm.metrics) > 0 {
		memUsage = pm.metrics[len(pm.metrics)-1].MemoryUsageMB
	}
	
	return SystemHealth{
		Status:           status,
		Timestamp:        time.Now(),
		AvgResponseTime:  avgResponseTime,
		SuccessRate:      successRate,
		RequestsPerMin:   requestsPerMin,
		ErrorCount:       pm.errorCount,
		MemoryUsageMB:    memUsage,
		UptimeSeconds:    int64(uptime.Seconds()),
		HealthScore:      healthScore,
	}
}

// calculateHealthScore computes a health score based on key metrics
func (pm *PerformanceMonitor) calculateHealthScore(avgResponseTime, successRate float64) int {
	score := 100
	
	// Penalize high response times
	if avgResponseTime > 100 {
		score -= int((avgResponseTime - 100) / 10)
	}
	
	// Penalize low success rates
	if successRate < 100 {
		score -= int((100 - successRate) * 2)
	}
	
	// Ensure score is within bounds
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	
	return score
}

// saveHealthData saves health metrics to JSON file
func (pm *PerformanceMonitor) saveHealthData(health SystemHealth) {
	filename := fmt.Sprintf("health_metrics_%s.json", 
		time.Now().Format("20060102"))
	
	// Read existing data
	var healthHistory []SystemHealth
	if data, err := os.ReadFile(filename); err == nil {
		json.Unmarshal(data, &healthHistory)
	}
	
	// Append new health data
	healthHistory = append(healthHistory, health)
	
	// Keep only last 24 hours of data (assuming 1 measurement per minute)
	if len(healthHistory) > 1440 {
		healthHistory = healthHistory[len(healthHistory)-1440:]
	}
	
	// Save updated data
	file, err := os.Create(filename)
	if err != nil {
		return
	}
	defer file.Close()
	
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encoder.Encode(healthHistory)
}

// GenerateReport creates a detailed performance report
func (pm *PerformanceMonitor) GenerateReport() {
	if len(pm.metrics) == 0 {
		fmt.Println("No metrics available for report generation")
		return
	}
	
	reportFile := fmt.Sprintf("performance_report_%s.json", 
		time.Now().Format("20060102_150405"))
	
	report := map[string]interface{}{
		"monitoring_period": map[string]interface{}{
			"start_time": pm.startTime,
			"end_time":   time.Now(),
			"duration":   time.Since(pm.startTime).String(),
		},
		"summary": map[string]interface{}{
			"total_requests":    pm.totalRequests,
			"success_count":     pm.successCount,
			"error_count":       pm.errorCount,
			"success_rate":      float64(pm.successCount) / float64(pm.totalRequests) * 100,
			"avg_response_time": float64(pm.totalResponseTime) / float64(pm.totalRequests),
		},
		"metrics": pm.metrics,
		"system_health": pm.calculateSystemHealth(),
	}
	
	file, err := os.Create(reportFile)
	if err != nil {
		fmt.Printf("Error creating report: %v\n", err)
		return
	}
	defer file.Close()
	
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(report)
	if err != nil {
		fmt.Printf("Error writing report: %v\n", err)
		return
	}
	
	fmt.Printf("📊 Performance report saved to: %s\n", reportFile)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run performance_monitor.go <target_url> [interval_seconds]")
		fmt.Println("Example: go run performance_monitor.go http://localhost:8080 5")
		os.Exit(1)
	}
	
	targetURL := os.Args[1]
	interval := 5 * time.Second
	
	// Parse optional interval parameter
	if len(os.Args) > 2 {
		if seconds, err := time.ParseDuration(os.Args[2] + "s"); err == nil {
			interval = seconds
		}
	}
	
	monitor := NewPerformanceMonitor(targetURL, interval)
	
	fmt.Printf("🔍 Performance Monitoring Suite v1.0\n")
	fmt.Printf("Target: %s\n", targetURL)
	fmt.Printf("Monitoring Interval: %v\n\n", interval)
	
	// Start monitoring (this will run indefinitely)
	monitor.Start()
}