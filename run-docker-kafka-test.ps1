# PowerShell Script untuk Menjalankan Pengujian Kafka dalam Docker
# Pengujian beban dengan 100 request

param(
    [int]$MessageCount = 100,
    [int]$BatchSize = 10,
    [int]$Concurrency = 5,
    [string]$TopicPrefix = "docker-test",
    [switch]$CleanUp,
    [switch]$ShowLogs,
    [switch]$Help
)

function Show-Help {
    Write-Host "🐳 Docker Kafka Performance Test - PowerShell Script" -ForegroundColor Cyan
    Write-Host "=================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "PENGGUNAAN:" -ForegroundColor Yellow
    Write-Host "  .\run-docker-kafka-test.ps1 [OPTIONS]"
    Write-Host ""
    Write-Host "OPTIONS:" -ForegroundColor Yellow
    Write-Host "  -MessageCount <int>    Jumlah pesan untuk dikirim (default: 100)"
    Write-Host "  -BatchSize <int>       Ukuran batch untuk pengiriman (default: 10)"
    Write-Host "  -Concurrency <int>     Jumlah worker concurrent (default: 5)"
    Write-Host "  -TopicPrefix <string>  Prefix untuk nama topic (default: 'docker-test')"
    Write-Host "  -CleanUp               Bersihkan container setelah selesai"
    Write-Host "  -ShowLogs              Tampilkan log container secara real-time"
    Write-Host "  -Help                  Tampilkan bantuan ini"
    Write-Host ""
    Write-Host "CONTOH:" -ForegroundColor Green
    Write-Host "  .\run-docker-kafka-test.ps1 -MessageCount 100 -BatchSize 10"
    Write-Host "  .\run-docker-kafka-test.ps1 -MessageCount 500 -Concurrency 10 -CleanUp"
    Write-Host "  .\run-docker-kafka-test.ps1 -ShowLogs"
    Write-Host ""
}

function Test-DockerInstalled {
    try {
        $dockerVersion = docker --version 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ Docker terdeteksi: $dockerVersion" -ForegroundColor Green
            return $true
        }
    } catch {
        Write-Host "❌ Docker tidak terdeteksi atau tidak berjalan" -ForegroundColor Red
        Write-Host "   Pastikan Docker Desktop sudah terinstall dan berjalan" -ForegroundColor Yellow
        return $false
    }
    return $false
}

function Test-DockerComposeInstalled {
    try {
        $composeVersion = docker-compose --version 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ Docker Compose terdeteksi: $composeVersion" -ForegroundColor Green
            return $true
        }
    } catch {
        # Try docker compose (newer syntax)
        try {
            $composeVersion = docker compose version 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "✅ Docker Compose terdeteksi: $composeVersion" -ForegroundColor Green
                return $true
            }
        } catch {
            Write-Host "❌ Docker Compose tidak terdeteksi" -ForegroundColor Red
            return $false
        }
    }
    return $false
}

function Start-KafkaServices {
    Write-Host "🚀 Memulai layanan Kafka dengan Docker Compose..." -ForegroundColor Cyan
    
    # Set environment variables
    $env:TEST_MESSAGE_COUNT = $MessageCount
    $env:TEST_BATCH_SIZE = $BatchSize
    $env:TEST_CONCURRENCY = $Concurrency
    $env:KAFKA_TOPIC_PREFIX = $TopicPrefix
    
    Write-Host "📋 Konfigurasi pengujian:" -ForegroundColor Yellow
    Write-Host "   - Message Count: $MessageCount"
    Write-Host "   - Batch Size: $BatchSize"
    Write-Host "   - Concurrency: $Concurrency"
    Write-Host "   - Topic Prefix: $TopicPrefix"
    Write-Host ""
    
    # Start services
    try {
        Write-Host "🔧 Membangun dan memulai container..." -ForegroundColor Blue
        docker-compose -f docker-compose.kafka.yml up -d --build
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ Layanan Kafka berhasil dimulai" -ForegroundColor Green
            return $true
        } else {
            Write-Host "❌ Gagal memulai layanan Kafka" -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "❌ Error saat memulai layanan: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Wait-ForKafkaReady {
    Write-Host "⏳ Menunggu Kafka siap..." -ForegroundColor Yellow
    
    $maxAttempts = 30
    $attempt = 1
    
    while ($attempt -le $maxAttempts) {
        Write-Host "   Percobaan $attempt/$maxAttempts - Memeriksa status Kafka..." -ForegroundColor Gray
        
        # Check if Kafka container is healthy
        $kafkaStatus = docker inspect kafka-broker --format='{{.State.Health.Status}}' 2>$null
        
        if ($kafkaStatus -eq "healthy") {
            Write-Host "✅ Kafka siap untuk pengujian!" -ForegroundColor Green
            return $true
        }
        
        Start-Sleep -Seconds 10
        $attempt++
    }
    
    Write-Host "❌ Timeout: Kafka tidak siap setelah $maxAttempts percobaan" -ForegroundColor Red
    Write-Host "📋 Status container:" -ForegroundColor Yellow
    docker-compose -f docker-compose.kafka.yml ps
    return $false
}

function Run-KafkaTests {
    Write-Host "🧪 Menjalankan pengujian Kafka..." -ForegroundColor Cyan
    
    try {
        # Run tests in the go-app container
        Write-Host "📤 Menjalankan pengujian performa..." -ForegroundColor Blue
        docker exec kafka-go-app go test -v ./test -run TestKafka100Messages -timeout 10m
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ Pengujian performa berhasil" -ForegroundColor Green
        } else {
            Write-Host "⚠️  Pengujian performa gagal, melanjutkan dengan benchmark" -ForegroundColor Yellow
        }
        
        # Run benchmark
        Write-Host "📊 Menjalankan benchmark..." -ForegroundColor Blue
        docker exec kafka-go-app go test -v ./test -bench=BenchmarkKafka100Messages -benchmem -timeout 10m
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ Benchmark berhasil" -ForegroundColor Green
        } else {
            Write-Host "⚠️  Benchmark gagal" -ForegroundColor Yellow
        }
        
        return $true
    } catch {
        Write-Host "❌ Error saat menjalankan pengujian: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Show-TestResults {
    Write-Host "📊 Mengumpulkan hasil pengujian..." -ForegroundColor Cyan
    
    # Create results directory if not exists
    if (!(Test-Path "results")) {
        New-Item -ItemType Directory -Path "results" | Out-Null
    }
    
    # Copy results from container
    try {
        docker cp kafka-go-app:/app/results/. ./results/
        Write-Host "✅ Hasil pengujian disalin ke direktori ./results/" -ForegroundColor Green
        
        # Show summary
        $resultFiles = Get-ChildItem -Path "./results" -Filter "*.log" | Sort-Object LastWriteTime -Descending
        if ($resultFiles.Count -gt 0) {
            Write-Host "📄 File hasil pengujian:" -ForegroundColor Yellow
            foreach ($file in $resultFiles) {
                Write-Host "   - $($file.Name)" -ForegroundColor Gray
            }
        }
    } catch {
        Write-Host "⚠️  Tidak dapat mengumpulkan hasil: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Show-ContainerLogs {
    if ($ShowLogs) {
        Write-Host "📋 Menampilkan log container..." -ForegroundColor Cyan
        Write-Host "   (Tekan Ctrl+C untuk keluar dari log)" -ForegroundColor Gray
        Write-Host ""
        
        try {
            docker-compose -f docker-compose.kafka.yml logs -f go-app
        } catch {
            Write-Host "⚠️  Tidak dapat menampilkan log" -ForegroundColor Yellow
        }
    }
}

function Stop-KafkaServices {
    if ($CleanUp) {
        Write-Host "🧹 Membersihkan container..." -ForegroundColor Yellow
        
        try {
            docker-compose -f docker-compose.kafka.yml down -v
            Write-Host "✅ Container berhasil dibersihkan" -ForegroundColor Green
        } catch {
            Write-Host "⚠️  Error saat membersihkan container: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "ℹ️  Container masih berjalan. Gunakan -CleanUp untuk membersihkan" -ForegroundColor Blue
        Write-Host "   Atau jalankan: docker-compose -f docker-compose.kafka.yml down -v" -ForegroundColor Gray
    }
}

function Show-KafkaUI {
    Write-Host "🌐 Kafka UI tersedia di: http://localhost:8080" -ForegroundColor Cyan
    Write-Host "   Gunakan untuk memantau topic dan pesan" -ForegroundColor Gray
}

# Main execution
function Main {
    if ($Help) {
        Show-Help
        return
    }
    
    Write-Host "🐳 Docker Kafka Performance Test" -ForegroundColor Cyan
    Write-Host "================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Check prerequisites
    if (!(Test-DockerInstalled)) {
        exit 1
    }
    
    if (!(Test-DockerComposeInstalled)) {
        exit 1
    }
    
    # Start Kafka services
    if (!(Start-KafkaServices)) {
        exit 1
    }
    
    # Wait for Kafka to be ready
    if (!(Wait-ForKafkaReady)) {
        Write-Host "❌ Kafka tidak siap, menghentikan pengujian" -ForegroundColor Red
        Stop-KafkaServices
        exit 1
    }
    
    # Show Kafka UI info
    Show-KafkaUI
    
    # Run tests
    $testSuccess = Run-KafkaTests
    
    # Show results
    Show-TestResults
    
    # Show logs if requested
    Show-ContainerLogs
    
    # Cleanup if requested
    Stop-KafkaServices
    
    if ($testSuccess) {
        Write-Host "🎉 Pengujian selesai dengan sukses!" -ForegroundColor Green
        Write-Host "📊 Periksa direktori ./results/ untuk detail hasil" -ForegroundColor Cyan
        exit 0
    } else {
        Write-Host "⚠️  Pengujian selesai dengan beberapa error" -ForegroundColor Yellow
        Write-Host "📊 Periksa direktori ./results/ untuk detail hasil" -ForegroundColor Cyan
        exit 1
    }
}

# Run main function
Main