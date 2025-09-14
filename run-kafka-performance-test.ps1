# Script PowerShell untuk menjalankan pengujian performa Kafka 10.000 pesan
# Author: Kafka Performance Tester
# Version: 1.0

param(
    [string]$Action = "help",
    [string]$Brokers = "localhost:9092",
    [int]$MessageCount = 10000,
    [int]$Concurrency = 10,
    [int]$BatchSize = 100
)

# Warna untuk output
$Red = "Red"
$Green = "Green"
$Yellow = "Yellow"
$Blue = "Blue"
$Cyan = "Cyan"
$Magenta = "Magenta"

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

function Show-Header {
    Write-ColorOutput "" 
    Write-ColorOutput "=" * 70 $Cyan
    Write-ColorOutput "🚀 KAFKA PERFORMANCE TESTER - 10.000 PESAN" $Cyan
    Write-ColorOutput "=" * 70 $Cyan
    Write-ColorOutput "📊 Konfigurasi:" $Yellow
    Write-ColorOutput "   • Brokers: $Brokers" $White
    Write-ColorOutput "   • Jumlah Pesan: $MessageCount" $White
    Write-ColorOutput "   • Concurrency: $Concurrency" $White
    Write-ColorOutput "   • Batch Size: $BatchSize" $White
    Write-ColorOutput "=" * 70 $Cyan
    Write-ColorOutput ""
}

function Test-KafkaConnection {
    Write-ColorOutput "🔍 Mengecek koneksi ke Kafka broker..." $Yellow
    
    # Test koneksi ke port Kafka
    try {
        $connection = Test-NetConnection -ComputerName "localhost" -Port 9092 -WarningAction SilentlyContinue
        if ($connection.TcpTestSucceeded) {
            Write-ColorOutput "✅ Kafka broker tersedia di $Brokers" $Green
            return $true
        } else {
            Write-ColorOutput "❌ Kafka broker tidak tersedia di $Brokers" $Red
            return $false
        }
    } catch {
        Write-ColorOutput "❌ Error saat mengecek koneksi: $($_.Exception.Message)" $Red
        return $false
    }
}

function Start-KafkaServer {
    Write-ColorOutput "🚀 Memulai Kafka server lokal..." $Yellow
    
    # Cek apakah Kafka sudah berjalan
    if (Test-KafkaConnection) {
        Write-ColorOutput "ℹ️ Kafka server sudah berjalan" $Blue
        return
    }
    
    # Jalankan script batch untuk start Kafka
    if (Test-Path "start-kafka-local.bat") {
        Write-ColorOutput "📋 Menjalankan start-kafka-local.bat..." $Yellow
        Start-Process -FilePath "start-kafka-local.bat" -ArgumentList "start" -NoNewWindow
        
        # Tunggu Kafka siap
        Write-ColorOutput "⏳ Menunggu Kafka server siap..." $Yellow
        $timeout = 60 # 60 detik timeout
        $elapsed = 0
        
        do {
            Start-Sleep -Seconds 2
            $elapsed += 2
            Write-Progress -Activity "Menunggu Kafka Server" -Status "Elapsed: $elapsed seconds" -PercentComplete (($elapsed / $timeout) * 100)
        } while (-not (Test-KafkaConnection) -and $elapsed -lt $timeout)
        
        Write-Progress -Activity "Menunggu Kafka Server" -Completed
        
        if (Test-KafkaConnection) {
            Write-ColorOutput "✅ Kafka server berhasil dimulai!" $Green
        } else {
            Write-ColorOutput "❌ Timeout: Kafka server tidak berhasil dimulai dalam $timeout detik" $Red
            Write-ColorOutput "💡 Silakan start Kafka server secara manual" $Yellow
            exit 1
        }
    } else {
        Write-ColorOutput "❌ File start-kafka-local.bat tidak ditemukan" $Red
        Write-ColorOutput "💡 Silakan start Kafka server secara manual" $Yellow
    }
}

function Test-GoEnvironment {
    Write-ColorOutput "🔍 Mengecek environment Go..." $Yellow
    
    # Cek apakah Go terinstall
    try {
        $goVersion = go version 2>$null
        if ($goVersion) {
            Write-ColorOutput "✅ Go terinstall: $goVersion" $Green
        } else {
            Write-ColorOutput "❌ Go tidak ditemukan" $Red
            return $false
        }
    } catch {
        Write-ColorOutput "❌ Go tidak ditemukan" $Red
        return $false
    }
    
    # Cek go.mod
    if (Test-Path "go.mod") {
        Write-ColorOutput "✅ go.mod ditemukan" $Green
    } else {
        Write-ColorOutput "❌ go.mod tidak ditemukan" $Red
        return $false
    }
    
    return $true
}

function Install-Dependencies {
    Write-ColorOutput "📦 Menginstall dependencies..." $Yellow
    
    try {
        $output = go mod tidy 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-ColorOutput "✅ Dependencies berhasil diinstall" $Green
        } else {
            Write-ColorOutput "❌ Gagal menginstall dependencies: $output" $Red
            return $false
        }
    } catch {
        Write-ColorOutput "❌ Error saat menginstall dependencies: $($_.Exception.Message)" $Red
        return $false
    }
    
    return $true
}

function Build-TestBinary {
    Write-ColorOutput "🔨 Membangun test binary..." $Yellow
    
    try {
        $output = go test -c ./test -o kafka_performance_test.exe 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-ColorOutput "✅ Test binary berhasil dibangun" $Green
            return $true
        } else {
            Write-ColorOutput "❌ Gagal membangun test binary: $output" $Red
            return $false
        }
    } catch {
        Write-ColorOutput "❌ Error saat membangun test binary: $($_.Exception.Message)" $Red
        return $false
    }
}

function Run-PerformanceTest {
    Write-ColorOutput "🧪 Menjalankan pengujian performa..." $Yellow
    Write-ColorOutput "📊 Target: $MessageCount pesan dengan $Concurrency worker" $Blue
    Write-ColorOutput ""
    
    # Set environment variables untuk konfigurasi
    $env:KAFKA_BROKERS = $Brokers
    
    try {
        # Jalankan test dengan verbose output
        $testCommand = "go test -v ./test -run TestKafka10000Messages -timeout 10m"
        Write-ColorOutput "🔧 Menjalankan: $testCommand" $Blue
        Write-ColorOutput ""
        
        # Jalankan test dan capture output
        $startTime = Get-Date
        Invoke-Expression $testCommand
        $endTime = Get-Date
        $duration = $endTime - $startTime
        
        Write-ColorOutput ""
        Write-ColorOutput "⏱️ Total waktu pengujian: $($duration.ToString('mm\:ss\.fff'))" $Magenta
        
        if ($LASTEXITCODE -eq 0) {
            Write-ColorOutput "✅ Pengujian performa berhasil diselesaikan!" $Green
        } else {
            Write-ColorOutput "❌ Pengujian performa gagal (exit code: $LASTEXITCODE)" $Red
        }
    } catch {
        Write-ColorOutput "❌ Error saat menjalankan pengujian: $($_.Exception.Message)" $Red
    }
}

function Run-BenchmarkTest {
    Write-ColorOutput "📈 Menjalankan benchmark test..." $Yellow
    
    try {
        $benchCommand = "go test -bench=BenchmarkKafka10000Messages -benchmem ./test"
        Write-ColorOutput "🔧 Menjalankan: $benchCommand" $Blue
        Write-ColorOutput ""
        
        Invoke-Expression $benchCommand
        
        if ($LASTEXITCODE -eq 0) {
            Write-ColorOutput "✅ Benchmark test berhasil diselesaikan!" $Green
        } else {
            Write-ColorOutput "❌ Benchmark test gagal" $Red
        }
    } catch {
        Write-ColorOutput "❌ Error saat menjalankan benchmark: $($_.Exception.Message)" $Red
    }
}

function Show-Help {
    Write-ColorOutput ""
    Write-ColorOutput "📋 KAFKA PERFORMANCE TESTER - BANTUAN" $Cyan
    Write-ColorOutput "=" * 50 $Cyan
    Write-ColorOutput ""
    Write-ColorOutput "🚀 Perintah yang tersedia:" $Yellow
    Write-ColorOutput "   test        - Jalankan pengujian performa 10.000 pesan" $White
    Write-ColorOutput "   benchmark   - Jalankan benchmark test" $White
    Write-ColorOutput "   start       - Start Kafka server lokal" $White
    Write-ColorOutput "   check       - Cek koneksi dan environment" $White
    Write-ColorOutput "   build       - Build test binary" $White
    Write-ColorOutput "   help        - Tampilkan bantuan ini" $White
    Write-ColorOutput ""
    Write-ColorOutput "💡 Contoh penggunaan:" $Yellow
    Write-ColorOutput "   .\run-kafka-performance-test.ps1 test" $White
    Write-ColorOutput "   .\run-kafka-performance-test.ps1 benchmark" $White
    Write-ColorOutput "   .\run-kafka-performance-test.ps1 start" $White
    Write-ColorOutput ""
    Write-ColorOutput "⚙️ Parameter opsional:" $Yellow
    Write-ColorOutput "   -Brokers <address>     (default: localhost:9092)" $White
    Write-ColorOutput "   -MessageCount <count>  (default: 10000)" $White
    Write-ColorOutput "   -Concurrency <workers> (default: 10)" $White
    Write-ColorOutput "   -BatchSize <size>      (default: 100)" $White
    Write-ColorOutput ""
    Write-ColorOutput "📝 Contoh dengan parameter:" $Yellow
    Write-ColorOutput "   .\run-kafka-performance-test.ps1 test -MessageCount 5000 -Concurrency 5" $White
    Write-ColorOutput ""
}

function Main {
    Show-Header
    
    switch ($Action.ToLower()) {
        "test" {
            if (-not (Test-GoEnvironment)) { exit 1 }
            if (-not (Install-Dependencies)) { exit 1 }
            if (-not (Test-KafkaConnection)) {
                Write-ColorOutput "⚠️ Kafka tidak tersedia. Mencoba start server..." $Yellow
                Start-KafkaServer
            }
            Run-PerformanceTest
        }
        "benchmark" {
            if (-not (Test-GoEnvironment)) { exit 1 }
            if (-not (Install-Dependencies)) { exit 1 }
            if (-not (Test-KafkaConnection)) {
                Write-ColorOutput "⚠️ Kafka tidak tersedia. Mencoba start server..." $Yellow
                Start-KafkaServer
            }
            Run-BenchmarkTest
        }
        "start" {
            Start-KafkaServer
        }
        "check" {
            Test-GoEnvironment
            Test-KafkaConnection
        }
        "build" {
            if (-not (Test-GoEnvironment)) { exit 1 }
            if (-not (Install-Dependencies)) { exit 1 }
            Build-TestBinary
        }
        "help" {
            Show-Help
        }
        default {
            Write-ColorOutput "❌ Perintah tidak dikenal: $Action" $Red
            Show-Help
        }
    }
    
    Write-ColorOutput ""
    Write-ColorOutput "🏁 Selesai!" $Green
}

# Jalankan main function
Main