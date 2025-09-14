package main

import (
	"context"
	"crypto/tls"
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

// ProgressiveTestConfig holds configuration for progressive load testing
type ProgressiveTestConfig struct {
	TargetURL     string        `json:"target_url"`
	StartRPS      int           `json:"start_rps"`
	MaxRPS        int           `json:"max_rps"`
	StepSize      int           `json:"step_size"`
	StepDuration  time.Duration `json:"step_duration"`
	Timeout       time.Duration `json:"timeout"`
}

// SimpleLoadTestResult holds basic load test results
type SimpleLoadTestResult struct {
	TotalRequests    int64         `json:"total_requests"`
	SuccessRequests  int64         `json:"success_requests"`
	FailedRequests   int64         `json:"failed_requests"`
	ActualRPS        float64       `json:"actual_rps"`
	ErrorRate        float64       `json:"error_rate"`
	AvgResponseTime  time.Duration `json:"avg_response_time"`
	P95ResponseTime  time.Duration `json:"p95_response_time"`
	TotalBytes       int64         `json:"total_bytes"`
	BytesPerSecond   float64       `json:"bytes_per_second"`
}

// ProgressiveTestResult holds results for each step
type ProgressiveTestResult struct {
	TargetRPS       int     `json:"target_rps"`
	ActualRPS       float64 `json:"actual_rps"`
	SuccessRate     float64 `json:"success_rate"`
	AvgResponseTime float64 `json:"avg_response_time_ms"`
	P95ResponseTime float64 `json:"p95_response_time_ms"`
	ErrorRate       float64 `json:"error_rate"`
	Throughput      float64 `json:"throughput_kbps"`
	MemoryUsage     float64 `json:"memory_usage_mb"`
	Goroutines      int     `json:"goroutines"`
	Saturated       bool    `json:"saturated"`
}

// SimpleLoadTester performs basic load testing
type SimpleLoadTester struct {
	targetURL   string
	rps         int
	duration    time.Duration
	timeout     time.Duration
	concurrency int
	client      *http.Client
}

// NewSimpleLoadTester creates a new simple load tester
func NewSimpleLoadTester(targetURL string, rps int, duration, timeout time.Duration) *SimpleLoadTester {
	concurrency := rps / 5
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > 5000 {
		concurrency = 5000
	}
	if rps > 5000 && concurrency < 2000 {
		concurrency = 2000
	}

	transport := &http.Transport{
		MaxIdleConns:        10000,
		MaxIdleConnsPerHost: 1000,
		MaxConnsPerHost:     1000,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		DisableKeepAlives:   false,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	return &SimpleLoadTester{
		targetURL:   targetURL,
		rps:         rps,
		duration:    duration,
		timeout:     timeout,
		concurrency: concurrency,
		client:      client,
	}
}

// RunSimpleLoadTest executes a simple load test
func (slt *SimpleLoadTester) RunSimpleLoadTest() (*SimpleLoadTestResult, error) {
	var totalRequests, successRequests, failedRequests, totalBytes int64
	var responseTimes []time.Duration
	var responseTimesMutex sync.Mutex

	ctx, cancel := context.WithTimeout(context.Background(), slt.duration)
	defer cancel()

	// Rate limiter
	ticker := time.NewTicker(time.Second / time.Duration(slt.rps))
	defer ticker.Stop()

	// Worker pool
	semaphore := make(chan struct{}, slt.concurrency)
	var wg sync.WaitGroup

	startTime := time.Now()

	for {
		select {
		case <-ctx.Done():
			goto done
		case <-ticker.C:
			select {
			case semaphore <- struct{}{}:
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer func() { <-semaphore }()

					reqStart := time.Now()
					resp, err := slt.client.Get(slt.targetURL)
					reqDuration := time.Since(reqStart)

					atomic.AddInt64(&totalRequests, 1)

					if err != nil {
						atomic.AddInt64(&failedRequests, 1)
						return
					}

					defer resp.Body.Close()
					body, _ := io.ReadAll(resp.Body)
					atomic.AddInt64(&totalBytes, int64(len(body)))

					if resp.StatusCode == 200 {
						atomic.AddInt64(&successRequests, 1)
					} else {
						atomic.AddInt64(&failedRequests, 1)
					}

					responseTimesMutex.Lock()
					responseTimes = append(responseTimes, reqDuration)
					responseTimesMutex.Unlock()
				}()
			default:
				// Skip if no worker available
			}
		}
	}

done:
	wg.Wait()
	elapsedTime := time.Since(startTime)

	// Calculate statistics
	actualRPS := float64(totalRequests) / elapsedTime.Seconds()
	errorRate := float64(failedRequests) / float64(totalRequests) * 100
	bytesPerSecond := float64(totalBytes) / elapsedTime.Seconds()

	// Calculate response time percentiles
	var avgResponseTime, p95ResponseTime time.Duration
	if len(responseTimes) > 0 {
		sort.Slice(responseTimes, func(i, j int) bool {
			return responseTimes[i] < responseTimes[j]
		})

		var total time.Duration
		for _, rt := range responseTimes {
			total += rt
		}
		avgResponseTime = total / time.Duration(len(responseTimes))

		p95Index := int(float64(len(responseTimes)) * 0.95)
		if p95Index >= len(responseTimes) {
			p95Index = len(responseTimes) - 1
		}
		p95ResponseTime = responseTimes[p95Index]
	}

	return &SimpleLoadTestResult{
		TotalRequests:   totalRequests,
		SuccessRequests: successRequests,
		FailedRequests:  failedRequests,
		ActualRPS:       actualRPS,
		ErrorRate:       errorRate,
		AvgResponseTime: avgResponseTime,
		P95ResponseTime: p95ResponseTime,
		TotalBytes:      totalBytes,
		BytesPerSecond:  bytesPerSecond,
	}, nil
}

// ProgressiveLoadTester manages progressive load testing
type ProgressiveLoadTester struct {
	config  ProgressiveTestConfig
	results []ProgressiveTestResult
}

// NewProgressiveLoadTester creates a new progressive load tester
func NewProgressiveLoadTester(config ProgressiveTestConfig) *ProgressiveLoadTester {
	return &ProgressiveLoadTester{
		config:  config,
		results: make([]ProgressiveTestResult, 0),
	}
}

// RunProgressiveTest executes progressive load testing
func (plt *ProgressiveLoadTester) RunProgressiveTest() error {
	fmt.Printf("🚀 Progressive Load Testing Started\n")
	fmt.Printf("Target: %s\n", plt.config.TargetURL)
	fmt.Printf("RPS Range: %d - %d (step: %d)\n", plt.config.StartRPS, plt.config.MaxRPS, plt.config.StepSize)
	fmt.Printf("Step Duration: %v\n\n", plt.config.StepDuration)
	
	var previousRPS float64
	var saturationPoint int
	
	for currentRPS := plt.config.StartRPS; currentRPS <= plt.config.MaxRPS; currentRPS += plt.config.StepSize {
		fmt.Printf("📊 Testing RPS: %d\n", currentRPS)
		
		// Create simple load tester for current step
		loadTester := NewSimpleLoadTester(plt.config.TargetURL, currentRPS, plt.config.StepDuration, plt.config.Timeout)
		
		// Run load test for this step
		results, err := loadTester.RunSimpleLoadTest()
		if err != nil {
			return fmt.Errorf("error running load test at %d RPS: %v", currentRPS, err)
		}
		
		// Get current memory stats
		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)
		memoryUsageMB := float64(memStats.Alloc) / 1024 / 1024
		
		// Calculate step result
		stepResult := ProgressiveTestResult{
			TargetRPS:       currentRPS,
			ActualRPS:       results.ActualRPS,
			SuccessRate:     float64(results.SuccessRequests) / float64(results.TotalRequests) * 100,
			AvgResponseTime: float64(results.AvgResponseTime.Milliseconds()),
			P95ResponseTime: float64(results.P95ResponseTime.Milliseconds()),
			ErrorRate:       results.ErrorRate,
			Throughput:      results.BytesPerSecond / 1024,
			MemoryUsage:     memoryUsageMB,
			Goroutines:      runtime.NumGoroutine(),
		}
		
		// Check for saturation
		if len(plt.results) > 0 {
			improvementRatio := stepResult.ActualRPS / previousRPS
			if improvementRatio < 1.1 && stepResult.ErrorRate > 1.0 {
				stepResult.Saturated = true
				saturationPoint = currentRPS
				fmt.Printf("⚠️  Saturation detected at %d RPS\n", currentRPS)
			}
		}
		
		plt.results = append(plt.results, stepResult)
		previousRPS = stepResult.ActualRPS
		
		// Print step summary
		fmt.Printf("   Actual RPS: %.2f (%.1f%% of target)\n", 
			stepResult.ActualRPS, stepResult.ActualRPS/float64(currentRPS)*100)
		fmt.Printf("   Success Rate: %.2f%%\n", stepResult.SuccessRate)
		fmt.Printf("   Avg Response Time: %.2fms\n", stepResult.AvgResponseTime)
		fmt.Printf("   Memory Usage: %.2fMB\n\n", stepResult.MemoryUsage)
		
		// Stop if saturated and error rate is too high
		if stepResult.Saturated && stepResult.ErrorRate > 5.0 {
			fmt.Printf("🛑 Stopping test due to high error rate at saturation point\n")
			break
		}
		
		// Brief pause between steps
		time.Sleep(3 * time.Second)
	}
	
	fmt.Printf("✅ Progressive Load Test Completed\n")
	if saturationPoint > 0 {
		fmt.Printf("📈 System saturation detected at: %d RPS\n", saturationPoint)
	}
	
	return nil
}

// PrintProgressiveResults displays comprehensive progressive test results
func (plt *ProgressiveLoadTester) PrintProgressiveResults() {
	fmt.Printf("\n" + strings.Repeat("=", 100) + "\n")
	fmt.Printf("📊 PROGRESSIVE LOAD TEST RESULTS\n")
	fmt.Printf(strings.Repeat("=", 100) + "\n\n")
	
	fmt.Printf("%-10s %-12s %-12s %-15s %-15s %-10s %-12s %-10s\n",
		"TARGET", "ACTUAL", "SUCCESS", "AVG_RT(ms)", "P95_RT(ms)", "ERROR%", "MEMORY(MB)", "STATUS")
	fmt.Printf(strings.Repeat("-", 100) + "\n")
	
	var maxActualRPS float64
	var optimalRPS int
	
	for _, result := range plt.results {
		status := "✅ OK"
		if result.Saturated {
			status = "⚠️  SAT"
		}
		if result.ErrorRate > 5 {
			status = "❌ ERR"
		}
		
		fmt.Printf("%-10d %-12.2f %-12.2f %-15.2f %-15.2f %-10.2f %-12.2f %-10s\n",
			result.TargetRPS,
			result.ActualRPS,
			result.SuccessRate,
			result.AvgResponseTime,
			result.P95ResponseTime,
			result.ErrorRate,
			result.MemoryUsage,
			status)
		
		if result.ActualRPS > maxActualRPS && result.ErrorRate < 1.0 {
			maxActualRPS = result.ActualRPS
			optimalRPS = result.TargetRPS
		}
	}
	
	fmt.Printf("\n📈 Performance Analysis:\n")
	fmt.Printf("   Maximum Sustainable RPS: %.2f\n", maxActualRPS)
	fmt.Printf("   Optimal Target RPS: %d\n", optimalRPS)
	fmt.Printf("   Recommended Operating RPS: %d (80%% of optimal)\n", int(float64(optimalRPS)*0.8))
	
	// Find performance characteristics
	var avgResponseTimeAtMax, memoryAtMax float64
	for _, result := range plt.results {
		if result.TargetRPS == optimalRPS {
			avgResponseTimeAtMax = result.AvgResponseTime
			memoryAtMax = result.MemoryUsage
			break
		}
	}
	
	fmt.Printf("\n🎯 System Characteristics at Optimal Load:\n")
	fmt.Printf("   Response Time: %.2fms\n", avgResponseTimeAtMax)
	fmt.Printf("   Memory Usage: %.2fMB\n", memoryAtMax)
	fmt.Printf("   Success Rate: 100%%\n")
	
	// Recommendations
	fmt.Printf("\n💡 Optimization Recommendations:\n")
	if maxActualRPS < 5000 {
		fmt.Printf("   • Consider horizontal scaling (multiple instances)\n")
		fmt.Printf("   • Optimize application code for better CPU utilization\n")
	}
	if avgResponseTimeAtMax > 50 {
		fmt.Printf("   • Optimize response time (current: %.2fms)\n", avgResponseTimeAtMax)
	}
	if memoryAtMax > 100 {
		fmt.Printf("   • Monitor memory usage (current: %.2fMB)\n", memoryAtMax)
	}
	fmt.Printf("   • Implement connection pooling and keep-alive optimization\n")
	fmt.Printf("   • Consider using a reverse proxy (nginx) for better performance\n")
}

// SaveProgressiveResults saves progressive test results to JSON
func (plt *ProgressiveLoadTester) SaveProgressiveResults() error {
	filename := fmt.Sprintf("progressive_loadtest_results_%s.json", 
		time.Now().Format("20060102_150405"))
	
	report := map[string]interface{}{
		"test_config": plt.config,
		"timestamp":   time.Now(),
		"results":     plt.results,
		"summary": map[string]interface{}{
			"total_steps": len(plt.results),
			"max_rps":     plt.getMaxActualRPS(),
			"optimal_rps": plt.getOptimalRPS(),
		},
	}
	
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(report)
	if err != nil {
		return err
	}
	
	fmt.Printf("💾 Progressive test results saved to: %s\n", filename)
	return nil
}

// getMaxActualRPS returns the maximum actual RPS achieved
func (plt *ProgressiveLoadTester) getMaxActualRPS() float64 {
	var maxRPS float64
	for _, result := range plt.results {
		if result.ActualRPS > maxRPS && result.ErrorRate < 1.0 {
			maxRPS = result.ActualRPS
		}
	}
	return maxRPS
}

// getOptimalRPS returns the optimal target RPS
func (plt *ProgressiveLoadTester) getOptimalRPS() int {
	var optimalRPS int
	var maxActualRPS float64
	
	for _, result := range plt.results {
		if result.ActualRPS > maxActualRPS && result.ErrorRate < 1.0 {
			maxActualRPS = result.ActualRPS
			optimalRPS = result.TargetRPS
		}
	}
	return optimalRPS
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run progressive_test.go <target_url> [max_rps] [step_size]")
		fmt.Println("Example: go run progressive_test.go http://localhost:8080 10000 500")
		os.Exit(1)
	}
	
	targetURL := os.Args[1]
	maxRPS := 10000
	stepSize := 500
	
	// Parse optional parameters
	if len(os.Args) > 2 {
		if n, err := fmt.Sscanf(os.Args[2], "%d", &maxRPS); n != 1 || err != nil {
			fmt.Printf("Invalid max RPS value: %s\n", os.Args[2])
			os.Exit(1)
		}
	}
	
	if len(os.Args) > 3 {
		if n, err := fmt.Sscanf(os.Args[3], "%d", &stepSize); n != 1 || err != nil {
			fmt.Printf("Invalid step size value: %s\n", os.Args[3])
			os.Exit(1)
		}
	}
	
	config := ProgressiveTestConfig{
		TargetURL:    targetURL,
		StartRPS:     500,
		MaxRPS:       maxRPS,
		StepSize:     stepSize,
		StepDuration: 30 * time.Second,
		Timeout:      5 * time.Second,
	}
	
	fmt.Printf("🔥 Progressive Load Testing Suite v1.0\n")
	fmt.Printf("Target: %s\n", config.TargetURL)
	fmt.Printf("RPS Range: %d - %d\n", config.StartRPS, config.MaxRPS)
	fmt.Printf("Step Size: %d\n", config.StepSize)
	fmt.Printf("Step Duration: %v\n", config.StepDuration)
	fmt.Printf("System: %d CPU cores, %s\n", runtime.NumCPU(), runtime.GOOS)
	fmt.Printf("⚠️  Warning: This will run for approximately %.1f minutes!\n\n", 
		float64((config.MaxRPS-config.StartRPS)/config.StepSize)*config.StepDuration.Minutes())
	
	progressiveTester := NewProgressiveLoadTester(config)
	
	err := progressiveTester.RunProgressiveTest()
	if err != nil {
		fmt.Printf("Error running progressive test: %v\n", err)
		os.Exit(1)
	}
	
	progressiveTester.PrintProgressiveResults()
	
	err = progressiveTester.SaveProgressiveResults()
	if err != nil {
		fmt.Printf("Error saving results: %v\n", err)
	}
	
	fmt.Printf("\n🎯 Progressive Load Testing Complete!\n")
}