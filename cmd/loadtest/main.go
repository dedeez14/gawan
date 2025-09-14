package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// LoadTestConfig holds configuration for load testing
type LoadTestConfig struct {
	TargetURL       string        `json:"target_url"`
	RequestsPerSec  int           `json:"requests_per_second"`
	Duration        time.Duration `json:"duration"`
	Timeout         time.Duration `json:"timeout"`
	Concurrency     int           `json:"concurrency"`
	Method          string        `json:"method"`
	Headers         map[string]string `json:"headers"`
	Body            string        `json:"body"`
	WarmupDuration  time.Duration `json:"warmup_duration"`
}

// RequestResult holds the result of a single request
type RequestResult struct {
	Timestamp    time.Time     `json:"timestamp"`
	Duration     time.Duration `json:"duration"`
	StatusCode   int           `json:"status_code"`
	Error        string        `json:"error,omitempty"`
	ResponseSize int64         `json:"response_size"`
}

// SystemMetrics holds system resource utilization data
type SystemMetrics struct {
	Timestamp   time.Time `json:"timestamp"`
	CPUPercent  float64   `json:"cpu_percent"`
	MemoryMB    float64   `json:"memory_mb"`
	Goroutines  int       `json:"goroutines"`
	HeapSizeMB  float64   `json:"heap_size_mb"`
}

// LoadTestResults holds comprehensive test results
type LoadTestResults struct {
	Config          LoadTestConfig    `json:"config"`
	StartTime       time.Time         `json:"start_time"`
	EndTime         time.Time         `json:"end_time"`
	TotalRequests   int64             `json:"total_requests"`
	SuccessRequests int64             `json:"success_requests"`
	FailedRequests  int64             `json:"failed_requests"`
	ErrorRate       float64           `json:"error_rate"`
	ActualRPS       float64           `json:"actual_rps"`
	ResponseTimes   ResponseTimeStats `json:"response_times"`
	StatusCodes     map[int]int64     `json:"status_codes"`
	Errors          map[string]int64  `json:"errors"`
	SystemMetrics   []SystemMetrics   `json:"system_metrics"`
	Throughput      ThroughputStats   `json:"throughput"`
}

// ResponseTimeStats holds response time statistics
type ResponseTimeStats struct {
	Min    time.Duration `json:"min"`
	Max    time.Duration `json:"max"`
	Mean   time.Duration `json:"mean"`
	Median time.Duration `json:"median"`
	P95    time.Duration `json:"p95"`
	P99    time.Duration `json:"p99"`
	StdDev time.Duration `json:"std_dev"`
}

// ThroughputStats holds throughput statistics
type ThroughputStats struct {
	BytesPerSecond float64 `json:"bytes_per_second"`
	TotalBytes     int64   `json:"total_bytes"`
	AvgResponseSize float64 `json:"avg_response_size"`
}

// LoadTester manages the load testing process
type LoadTester struct {
	config        LoadTestConfig
	client        *http.Client
	results       []RequestResult
	systemMetrics []SystemMetrics
	mu            sync.RWMutex
	totalRequests int64
	successCount  int64
	failureCount  int64
	totalBytes    int64
	statusCodes   map[int]int64
	errorCounts   map[string]int64
	ctx           context.Context
	cancel        context.CancelFunc
}

// NewLoadTester creates a new load tester instance
func NewLoadTester(config LoadTestConfig) *LoadTester {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &LoadTester{
		config: config,
		client: &http.Client{
			Timeout: config.Timeout,
			Transport: &http.Transport{
				MaxIdleConns:        config.Concurrency * 4,
				MaxIdleConnsPerHost: config.Concurrency * 2,
				MaxConnsPerHost:     config.Concurrency * 2,
				IdleConnTimeout:     60 * time.Second,
				TLSHandshakeTimeout: 5 * time.Second,
				DisableKeepAlives:   false,
			},
		},
		results:     make([]RequestResult, 0),
		statusCodes: make(map[int]int64),
		errorCounts: make(map[string]int64),
		ctx:         ctx,
		cancel:      cancel,
	}
}

// RunLoadTest executes the load test
func (lt *LoadTester) RunLoadTest() (*LoadTestResults, error) {
	fmt.Printf("\n🚀 Starting Load Test\n")
	fmt.Printf("Target: %s\n", lt.config.TargetURL)
	fmt.Printf("RPS Target: %d\n", lt.config.RequestsPerSec)
	fmt.Printf("Duration: %v\n", lt.config.Duration)
	fmt.Printf("Concurrency: %d\n", lt.config.Concurrency)
	fmt.Printf("Warmup: %v\n\n", lt.config.WarmupDuration)
	
	startTime := time.Now()
	
	// Start system monitoring
	go lt.monitorSystemMetrics()
	
	// Warmup phase
	if lt.config.WarmupDuration > 0 {
		fmt.Printf("🔥 Warmup phase started...\n")
		lt.runWarmup()
		fmt.Printf("✅ Warmup completed\n\n")
	}
	
	// Main load test
	fmt.Printf("⚡ Load test started...\n")
	lt.runMainTest()
	
	endTime := time.Now()
	fmt.Printf("\n✅ Load test completed!\n")
	
	// Calculate results
	results := lt.calculateResults(startTime, endTime)
	
	return results, nil
}

// runWarmup performs warmup requests
func (lt *LoadTester) runWarmup() {
	warmupRPS := lt.config.RequestsPerSec / 4 // 25% of target RPS for warmup
	if warmupRPS < 1 {
		warmupRPS = 1
	}
	
	interval := time.Second / time.Duration(warmupRPS)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	
	warmupCtx, cancel := context.WithTimeout(lt.ctx, lt.config.WarmupDuration)
	defer cancel()
	
	for {
		select {
		case <-warmupCtx.Done():
			return
		case <-ticker.C:
			go lt.makeRequest(true) // warmup flag
		}
	}
}

// runMainTest performs the main load test
func (lt *LoadTester) runMainTest() {
	interval := time.Second / time.Duration(lt.config.RequestsPerSec)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	
	testCtx, cancel := context.WithTimeout(lt.ctx, lt.config.Duration)
	defer cancel()
	
	// Rate limiter to maintain consistent RPS
	requestChan := make(chan struct{}, lt.config.Concurrency)
	
	// Worker pool
	var wg sync.WaitGroup
	for i := 0; i < lt.config.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-testCtx.Done():
					return
				case <-requestChan:
					lt.makeRequest(false)
				}
			}
		}()
	}
	
	// Request scheduler
	go func() {
		for {
			select {
			case <-testCtx.Done():
				close(requestChan)
				return
			case <-ticker.C:
				select {
				case requestChan <- struct{}{}:
				default:
					// Channel full, skip this request
				}
			}
		}
	}()
	
	wg.Wait()
}

// makeRequest performs a single HTTP request
func (lt *LoadTester) makeRequest(isWarmup bool) {
	start := time.Now()
	
	req, err := http.NewRequestWithContext(lt.ctx, lt.config.Method, lt.config.TargetURL, nil)
	if err != nil {
		if !isWarmup {
			lt.recordError("request_creation_error", err.Error())
		}
		return
	}
	
	// Add headers
	for key, value := range lt.config.Headers {
		req.Header.Set(key, value)
	}
	
	resp, err := lt.client.Do(req)
	duration := time.Since(start)
	
	if !isWarmup {
		atomic.AddInt64(&lt.totalRequests, 1)
	}
	
	result := RequestResult{
		Timestamp: start,
		Duration:  duration,
	}
	
	if err != nil {
		result.Error = err.Error()
		if !isWarmup {
			atomic.AddInt64(&lt.failureCount, 1)
			lt.recordError("http_error", err.Error())
		}
	} else {
		defer resp.Body.Close()
		
		result.StatusCode = resp.StatusCode
		
		// Read response body to measure size
		body, _ := io.ReadAll(resp.Body)
		result.ResponseSize = int64(len(body))
		
		if !isWarmup {
			atomic.AddInt64(&lt.totalBytes, result.ResponseSize)
			
			if resp.StatusCode >= 200 && resp.StatusCode < 400 {
				atomic.AddInt64(&lt.successCount, 1)
			} else {
				atomic.AddInt64(&lt.failureCount, 1)
				lt.recordError(fmt.Sprintf("status_%d", resp.StatusCode), "")
			}
			
			lt.recordStatusCode(resp.StatusCode)
		}
	}
	
	if !isWarmup {
		lt.recordResult(result)
	}
}

// recordResult safely records a request result
func (lt *LoadTester) recordResult(result RequestResult) {
	lt.mu.Lock()
	lt.results = append(lt.results, result)
	lt.mu.Unlock()
}

// recordStatusCode safely records status code counts
func (lt *LoadTester) recordStatusCode(code int) {
	lt.mu.Lock()
	lt.statusCodes[code]++
	lt.mu.Unlock()
}

// recordError safely records error counts
func (lt *LoadTester) recordError(errorType, message string) {
	lt.mu.Lock()
	lt.errorCounts[errorType]++
	lt.mu.Unlock()
}

// monitorSystemMetrics monitors system resource utilization
func (lt *LoadTester) monitorSystemMetrics() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	var m runtime.MemStats
	
	for {
		select {
		case <-lt.ctx.Done():
			return
		case <-ticker.C:
			runtime.ReadMemStats(&m)
			
			metrics := SystemMetrics{
				Timestamp:  time.Now(),
				Goroutines: runtime.NumGoroutine(),
				HeapSizeMB: float64(m.HeapAlloc) / 1024 / 1024,
				MemoryMB:   float64(m.Sys) / 1024 / 1024,
			}
			
			lt.mu.Lock()
			lt.systemMetrics = append(lt.systemMetrics, metrics)
			lt.mu.Unlock()
		}
	}
}

// calculateResults computes final test results and statistics
func (lt *LoadTester) calculateResults(startTime, endTime time.Time) *LoadTestResults {
	lt.mu.RLock()
	defer lt.mu.RUnlock()
	
	totalDuration := endTime.Sub(startTime)
	actualRPS := float64(lt.totalRequests) / totalDuration.Seconds()
	errorRate := float64(lt.failureCount) / float64(lt.totalRequests) * 100
	
	// Calculate response time statistics
	responseTimes := make([]time.Duration, len(lt.results))
	for i, result := range lt.results {
		responseTimes[i] = result.Duration
	}
	
	responseStats := calculateResponseTimeStats(responseTimes)
	
	// Calculate throughput
	throughput := ThroughputStats{
		BytesPerSecond:  float64(lt.totalBytes) / totalDuration.Seconds(),
		TotalBytes:      lt.totalBytes,
		AvgResponseSize: float64(lt.totalBytes) / float64(lt.totalRequests),
	}
	
	return &LoadTestResults{
		Config:          lt.config,
		StartTime:       startTime,
		EndTime:         endTime,
		TotalRequests:   lt.totalRequests,
		SuccessRequests: lt.successCount,
		FailedRequests:  lt.failureCount,
		ErrorRate:       errorRate,
		ActualRPS:       actualRPS,
		ResponseTimes:   responseStats,
		StatusCodes:     lt.statusCodes,
		Errors:          lt.errorCounts,
		SystemMetrics:   lt.systemMetrics,
		Throughput:      throughput,
	}
}

// calculateResponseTimeStats computes response time statistics
func calculateResponseTimeStats(durations []time.Duration) ResponseTimeStats {
	if len(durations) == 0 {
		return ResponseTimeStats{}
	}
	
	sort.Slice(durations, func(i, j int) bool {
		return durations[i] < durations[j]
	})
	
	n := len(durations)
	min := durations[0]
	max := durations[n-1]
	
	// Calculate mean
	var sum time.Duration
	for _, d := range durations {
		sum += d
	}
	mean := sum / time.Duration(n)
	
	// Calculate median
	var median time.Duration
	if n%2 == 0 {
		median = (durations[n/2-1] + durations[n/2]) / 2
	} else {
		median = durations[n/2]
	}
	
	// Calculate percentiles
	p95 := durations[int(float64(n)*0.95)]
	p99 := durations[int(float64(n)*0.99)]
	
	// Calculate standard deviation
	var variance float64
	for _, d := range durations {
		diff := float64(d - mean)
		variance += diff * diff
	}
	variance /= float64(n)
	stdDev := time.Duration(variance)
	
	return ResponseTimeStats{
		Min:    min,
		Max:    max,
		Mean:   mean,
		Median: median,
		P95:    p95,
		P99:    p99,
		StdDev: stdDev,
	}
}

// PrintResults displays test results in a formatted way
func (lt *LoadTester) PrintResults(results *LoadTestResults) {
	fmt.Printf("\n" + strings.Repeat("=", 60) + "\n")
	fmt.Printf("📊 LOAD TEST RESULTS\n")
	fmt.Printf(strings.Repeat("=", 60) + "\n\n")
	
	fmt.Printf("🎯 Test Configuration:\n")
	fmt.Printf("   Target URL: %s\n", results.Config.TargetURL)
	fmt.Printf("   Target RPS: %d\n", results.Config.RequestsPerSec)
	fmt.Printf("   Duration: %v\n", results.Config.Duration)
	fmt.Printf("   Concurrency: %d\n\n", results.Config.Concurrency)
	
	fmt.Printf("📈 Performance Metrics:\n")
	fmt.Printf("   Total Requests: %d\n", results.TotalRequests)
	fmt.Printf("   Successful: %d (%.2f%%)\n", results.SuccessRequests, 
		float64(results.SuccessRequests)/float64(results.TotalRequests)*100)
	fmt.Printf("   Failed: %d (%.2f%%)\n", results.FailedRequests, results.ErrorRate)
	fmt.Printf("   Actual RPS: %.2f\n", results.ActualRPS)
	fmt.Printf("   RPS Achievement: %.1f%%\n\n", 
		results.ActualRPS/float64(results.Config.RequestsPerSec)*100)
	
	fmt.Printf("⏱️  Response Times:\n")
	fmt.Printf("   Min: %v\n", results.ResponseTimes.Min)
	fmt.Printf("   Max: %v\n", results.ResponseTimes.Max)
	fmt.Printf("   Mean: %v\n", results.ResponseTimes.Mean)
	fmt.Printf("   Median: %v\n", results.ResponseTimes.Median)
	fmt.Printf("   95th Percentile: %v\n", results.ResponseTimes.P95)
	fmt.Printf("   99th Percentile: %v\n\n", results.ResponseTimes.P99)
	
	fmt.Printf("📊 Throughput:\n")
	fmt.Printf("   Bytes/sec: %.2f KB/s\n", results.Throughput.BytesPerSecond/1024)
	fmt.Printf("   Total Bytes: %.2f MB\n", float64(results.Throughput.TotalBytes)/1024/1024)
	fmt.Printf("   Avg Response Size: %.2f bytes\n\n", results.Throughput.AvgResponseSize)
	
	if len(results.StatusCodes) > 0 {
		fmt.Printf("📋 Status Code Distribution:\n")
		for code, count := range results.StatusCodes {
			percentage := float64(count) / float64(results.TotalRequests) * 100
			fmt.Printf("   %d: %d (%.2f%%)\n", code, count, percentage)
		}
		fmt.Println()
	}
	
	if len(results.Errors) > 0 {
		fmt.Printf("❌ Error Distribution:\n")
		for errorType, count := range results.Errors {
			percentage := float64(count) / float64(results.TotalRequests) * 100
			fmt.Printf("   %s: %d (%.2f%%)\n", errorType, count, percentage)
		}
		fmt.Println()
	}
	
	// System resource summary
	if len(results.SystemMetrics) > 0 {
		lastMetric := results.SystemMetrics[len(results.SystemMetrics)-1]
		fmt.Printf("💻 System Resources (Final):\n")
		fmt.Printf("   Goroutines: %d\n", lastMetric.Goroutines)
		fmt.Printf("   Heap Size: %.2f MB\n", lastMetric.HeapSizeMB)
		fmt.Printf("   Memory Usage: %.2f MB\n\n", lastMetric.MemoryMB)
	}
	
	// Performance assessment
	lt.assessPerformance(results)
}

// assessPerformance provides performance assessment and recommendations
func (lt *LoadTester) assessPerformance(results *LoadTestResults) {
	fmt.Printf("🎯 Performance Assessment:\n")
	
	rpsAchievement := results.ActualRPS / float64(results.Config.RequestsPerSec) * 100
	errorRate := results.ErrorRate
	p95ResponseTime := results.ResponseTimes.P95
	
	if rpsAchievement >= 95 && errorRate < 1 && p95ResponseTime < 500*time.Millisecond {
		fmt.Printf("   ✅ EXCELLENT: System handles target load very well\n")
	} else if rpsAchievement >= 80 && errorRate < 5 && p95ResponseTime < 1*time.Second {
		fmt.Printf("   ✅ GOOD: System performs well under load\n")
	} else if rpsAchievement >= 60 && errorRate < 10 && p95ResponseTime < 2*time.Second {
		fmt.Printf("   ⚠️  ACCEPTABLE: System shows some stress under load\n")
	} else {
		fmt.Printf("   ❌ POOR: System struggles under target load\n")
	}
	
	fmt.Printf("\n📋 Recommendations:\n")
	if rpsAchievement < 90 {
		fmt.Printf("   • Consider scaling up server resources\n")
		fmt.Printf("   • Optimize application performance\n")
	}
	if errorRate > 5 {
		fmt.Printf("   • Investigate error causes and fix issues\n")
		fmt.Printf("   • Implement better error handling\n")
	}
	if p95ResponseTime > 1*time.Second {
		fmt.Printf("   • Optimize slow endpoints\n")
		fmt.Printf("   • Consider caching strategies\n")
	}
	fmt.Println()
}

// SaveResults saves test results to JSON file
func (lt *LoadTester) SaveResults(results *LoadTestResults) error {
	filename := fmt.Sprintf("loadtest_results_%s.json", 
		time.Now().Format("20060102_150405"))
	
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(results)
	if err != nil {
		return err
	}
	
	fmt.Printf("💾 Results saved to: %s\n", filename)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <target_url> [rps] [duration]")
		fmt.Println("Example: go run main.go http://localhost:8080 1000 30s")
		os.Exit(1)
	}
	
	targetURL := os.Args[1]
	rps := 1000
	duration := 30 * time.Second
	
	// Parse optional RPS parameter
	if len(os.Args) > 2 {
		if n, err := fmt.Sscanf(os.Args[2], "%d", &rps); n != 1 || err != nil {
			fmt.Printf("Invalid RPS value: %s\n", os.Args[2])
			os.Exit(1)
		}
	}
	
	// Parse optional duration parameter
	if len(os.Args) > 3 {
		if d, err := time.ParseDuration(os.Args[3]); err != nil {
			fmt.Printf("Invalid duration: %s\n", os.Args[3])
			os.Exit(1)
		} else {
			duration = d
		}
	}
	
	config := LoadTestConfig{
		TargetURL:      targetURL,
		RequestsPerSec: rps,
		Duration:       duration,
		Timeout:        5 * time.Second, // Reduced timeout for high load
		Concurrency:    rps / 5, // 5 RPS per goroutine for better performance
		Method:         "GET",
		Headers: map[string]string{
			"User-Agent": "LoadTester/1.0",
			"Accept":     "*/*",
			"Connection": "keep-alive",
		},
		WarmupDuration: 10 * time.Second, // Longer warmup for high load
	}
	
	// Ensure optimal concurrency for high load
	if config.Concurrency < 1 {
		config.Concurrency = 1
	}
	if config.Concurrency > 5000 {
		config.Concurrency = 5000
	}
	// For very high RPS, ensure minimum concurrency
	if rps > 5000 && config.Concurrency < 2000 {
		config.Concurrency = 2000
	}
	
	fmt.Printf("🔥 Load Testing Suite v1.0\n")
	fmt.Printf("Target: %s\n", config.TargetURL)
	fmt.Printf("Target RPS: %d\n", config.RequestsPerSec)
	fmt.Printf("Duration: %v\n", config.Duration)
	fmt.Printf("Concurrency: %d\n", config.Concurrency)
	fmt.Printf("⚠️  Warning: Ensure you have permission to test this target!\n")
	
	loadTester := NewLoadTester(config)
	
	results, err := loadTester.RunLoadTest()
	if err != nil {
		fmt.Printf("Error running load test: %v\n", err)
		os.Exit(1)
	}
	
	loadTester.PrintResults(results)
	
	err = loadTester.SaveResults(results)
	if err != nil {
		fmt.Printf("Error saving results: %v\n", err)
	}
	
	if runtime.GOOS == "windows" {
		fmt.Printf("\nPress Enter to exit...")
		bufio.NewReader(os.Stdin).ReadBytes('\n')
	}
}