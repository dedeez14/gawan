@echo off
REM Script untuk menjalankan Kafka server lokal tanpa Docker
REM Pastikan Java sudah terinstall dan JAVA_HOME sudah diset

setlocal enabledelayedexpansion

REM Konfigurasi path Kafka (sesuaikan dengan instalasi Anda)
set KAFKA_HOME=C:\kafka
set KAFKA_VERSION=2.13-3.6.0
set KAFKA_DIR=%KAFKA_HOME%\kafka_%KAFKA_VERSION%

REM Periksa apakah Kafka sudah terinstall
if not exist "%KAFKA_DIR%" (
    echo ❌ Kafka tidak ditemukan di %KAFKA_DIR%
    echo 📥 Silakan download Kafka dari: https://kafka.apache.org/downloads
    echo 📁 Extract ke: %KAFKA_HOME%
    echo 🔧 Atau ubah KAFKA_HOME di script ini sesuai lokasi instalasi Anda
    pause
    exit /b 1
)

REM Periksa Java
java -version >nul 2>&1
if errorlevel 1 (
    echo ❌ Java tidak ditemukan. Pastikan Java sudah terinstall dan ada di PATH
    echo 📥 Download Java dari: https://adoptium.net/
    pause
    exit /b 1
)

echo 🚀 Memulai Kafka Server Lokal...
echo 📁 Kafka Directory: %KAFKA_DIR%
echo.

REM Pindah ke direktori Kafka
cd /d "%KAFKA_DIR%"

REM Buat direktori logs jika belum ada
if not exist "logs" mkdir logs

REM Fungsi untuk menjalankan perintah
if "%1"=="" goto :help
if "%1"=="help" goto :help
if "%1"=="start" goto :start
if "%1"=="stop" goto :stop
if "%1"=="status" goto :status
if "%1"=="create-topic" goto :create_topic
if "%1"=="list-topics" goto :list_topics
if "%1"=="test" goto :test
if "%1"=="clean" goto :clean
goto :help

:help
echo 📋 KAFKA LOCAL SERVER MANAGER
echo ================================
echo.
echo 🚀 Perintah yang tersedia:
echo   start        - Mulai Zookeeper dan Kafka server
echo   stop         - Hentikan Kafka server dan Zookeeper
echo   status       - Cek status server
echo   create-topic - Buat topic untuk testing
echo   list-topics  - Lihat daftar topic
echo   test         - Test koneksi ke Kafka
echo   clean        - Bersihkan log files
echo   help         - Tampilkan bantuan ini
echo.
echo 💡 Contoh penggunaan:
echo   start-kafka-local.bat start
echo   start-kafka-local.bat create-topic
echo   start-kafka-local.bat test
echo.
goto :eof

:start
echo 🔄 Memulai Zookeeper...
start "Zookeeper" cmd /k "bin\windows\zookeeper-server-start.bat config\zookeeper.properties"
echo ⏳ Menunggu Zookeeper siap (10 detik)...
timeout /t 10 /nobreak >nul

echo 🔄 Memulai Kafka Server...
start "Kafka Server" cmd /k "bin\windows\kafka-server-start.bat config\server.properties"
echo ⏳ Menunggu Kafka Server siap (15 detik)...
timeout /t 15 /nobreak >nul

echo ✅ Kafka Server berhasil dimulai!
echo 🌐 Broker tersedia di: localhost:9092
echo 📊 Zookeeper tersedia di: localhost:2181
echo.
echo 💡 Gunakan perintah berikut untuk membuat topic:
echo   %~nx0 create-topic
echo.
goto :eof

:stop
echo 🛑 Menghentikan Kafka Server...
taskkill /f /im java.exe /fi "WINDOWTITLE eq Kafka Server*" 2>nul
echo 🛑 Menghentikan Zookeeper...
taskkill /f /im java.exe /fi "WINDOWTITLE eq Zookeeper*" 2>nul
echo ✅ Kafka Server dan Zookeeper dihentikan
goto :eof

:status
echo 🔍 Mengecek status Kafka Server...
netstat -an | findstr :9092 >nul
if errorlevel 1 (
    echo ❌ Kafka Server tidak berjalan (port 9092 tidak aktif)
) else (
    echo ✅ Kafka Server berjalan (port 9092 aktif)
)

netstat -an | findstr :2181 >nul
if errorlevel 1 (
    echo ❌ Zookeeper tidak berjalan (port 2181 tidak aktif)
) else (
    echo ✅ Zookeeper berjalan (port 2181 aktif)
)
goto :eof

:create_topic
echo 📝 Membuat topic untuk testing...
bin\windows\kafka-topics.bat --create --topic test-topic --bootstrap-server localhost:9092 --partitions 6 --replication-factor 1
bin\windows\kafka-topics.bat --create --topic perf-test --bootstrap-server localhost:9092 --partitions 6 --replication-factor 1
echo ✅ Topic berhasil dibuat!
goto :eof

:list_topics
echo 📋 Daftar topic yang tersedia:
bin\windows\kafka-topics.bat --list --bootstrap-server localhost:9092
goto :eof

:test
echo 🧪 Testing koneksi ke Kafka...
echo 📤 Mengirim test message...
echo "Test message from batch script" | bin\windows\kafka-console-producer.bat --topic test-topic --bootstrap-server localhost:9092
echo ✅ Test message berhasil dikirim!
echo.
echo 📥 Untuk melihat pesan, jalankan consumer di terminal terpisah:
echo bin\windows\kafka-console-consumer.bat --topic test-topic --from-beginning --bootstrap-server localhost:9092
goto :eof

:clean
echo 🧹 Membersihkan log files...
if exist "logs" (
    rmdir /s /q logs
    mkdir logs
    echo ✅ Log files berhasil dibersihkan
) else (
    echo ℹ️ Tidak ada log files untuk dibersihkan
)
goto :eof

:eof
echo.
echo 💡 Tip: Gunakan '%~nx0 help' untuk melihat semua perintah yang tersedia