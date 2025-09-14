# 🚀 Panduan Menjalankan Kafka dan Pengujian 10.000 Pesan Tanpa Docker

## 📋 Prasyarat

### 1. Install Java
- Download dan install Java 8 atau yang lebih baru dari [Adoptium](https://adoptium.net/)
- Pastikan `JAVA_HOME` sudah diset dan Java ada di PATH
- Verifikasi dengan: `java -version`

### 2. Download Kafka
- Download Kafka dari [Apache Kafka Downloads](https://kafka.apache.org/downloads)
- Pilih versi terbaru (contoh: kafka_2.13-3.6.0.tgz)
- Extract ke `C:\kafka\kafka_2.13-3.6.0`

## 🔧 Setup Kafka Server

### Opsi 1: Menggunakan Script Otomatis

1. **Edit konfigurasi di `start-kafka-local.bat`**:
   ```batch
   set KAFKA_HOME=C:\kafka
   set KAFKA_VERSION=2.13-3.6.0
   ```
   Sesuaikan dengan lokasi dan versi Kafka Anda.

2. **Jalankan Kafka server**:
   ```cmd
   start-kafka-local.bat start
   ```

3. **Buat topic untuk testing**:
   ```cmd
   start-kafka-local.bat create-topic
   ```

4. **Cek status**:
   ```cmd
   start-kafka-local.bat status
   ```

### Opsi 2: Manual Setup

1. **Buka Command Prompt sebagai Administrator**

2. **Pindah ke direktori Kafka**:
   ```cmd
   cd C:\kafka\kafka_2.13-3.6.0
   ```

3. **Start Zookeeper** (terminal pertama):
   ```cmd
   bin\windows\zookeeper-server-start.bat config\zookeeper.properties
   ```

4. **Start Kafka Server** (terminal kedua):
   ```cmd
   bin\windows\kafka-server-start.bat config\server.properties
   ```

5. **Buat topic untuk testing** (terminal ketiga):
   ```cmd
   bin\windows\kafka-topics.bat --create --topic test-topic --bootstrap-server localhost:9092 --partitions 6 --replication-factor 1
   bin\windows\kafka-topics.bat --create --topic perf-test --bootstrap-server localhost:9092 --partitions 6 --replication-factor 1
   ```

## 🧪 Menjalankan Pengujian Performa 10.000 Pesan

### Metode 1: Menggunakan PowerShell Script (Direkomendasikan)

1. **Buka PowerShell sebagai Administrator**

2. **Pindah ke direktori project**:
   ```powershell
   cd C:\project\golang\tutorial
   ```

3. **Set execution policy** (jika diperlukan):
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

4. **Jalankan pengujian performa**:
   ```powershell
   .\run-kafka-performance-test.ps1 test
   ```

5. **Atau jalankan benchmark**:
   ```powershell
   .\run-kafka-performance-test.ps1 benchmark
   ```

### Metode 2: Menggunakan Go Test Langsung

1. **Pastikan dependencies terinstall**:
   ```cmd
   go mod tidy
   ```

2. **Jalankan test performa**:
   ```cmd
   go test -v ./test -run TestKafka10000Messages -timeout 10m
   ```

3. **Jalankan benchmark**:
   ```cmd
   go test -bench=BenchmarkKafka10000Messages -benchmem ./test
   ```

### Metode 3: Menggunakan Batch Script

1. **Jalankan test menggunakan batch script**:
   ```cmd
   .\kafka-test.bat kafka-test
   ```

## 📊 Konfigurasi Pengujian

### Parameter Default:
- **Jumlah Pesan**: 10.000
- **Concurrency**: 10 worker
- **Batch Size**: 100 pesan per batch
- **Partisi**: 6 partisi per topic
- **Timeout**: 10 menit
- **Broker**: localhost:9092

### Kustomisasi Parameter:
```powershell
# Contoh dengan parameter kustom
.\run-kafka-performance-test.ps1 test -MessageCount 5000 -Concurrency 5 -BatchSize 50
```

## 🔍 Monitoring dan Validasi

### 1. Cek Status Kafka
```cmd
netstat -an | findstr :9092
netstat -an | findstr :2181
```

### 2. Monitor Topic
```cmd
bin\windows\kafka-topics.bat --list --bootstrap-server localhost:9092
bin\windows\kafka-topics.bat --describe --topic perf-test --bootstrap-server localhost:9092
```

### 3. Monitor Consumer Lag
```cmd
bin\windows\kafka-consumer-groups.bat --bootstrap-server localhost:9092 --list
```

## 📈 Metrik Performa yang Diukur

### Produksi:
- **Throughput**: Pesan per detik yang berhasil dikirim
- **Latency**: Waktu rata-rata untuk mengirim satu pesan
- **Error Rate**: Persentase pesan yang gagal dikirim
- **Success Rate**: Persentase pesan yang berhasil dikirim

### Konsumsi:
- **Consumption Rate**: Pesan per detik yang berhasil dikonsumsi
- **Total Consumed**: Total pesan yang berhasil dikonsumsi
- **Consumption Percentage**: Persentase dari pesan yang dikirim

### Target Performa:
- ✅ **Throughput Minimum**: > 100 pesan/detik
- ✅ **Error Rate Maximum**: < 1%
- ✅ **Success Rate Minimum**: 100%
- ✅ **Consumption Rate Minimum**: > 90% dari pesan yang dikirim

## 🛠️ Troubleshooting

### Problem: Kafka tidak bisa start
**Solusi**:
1. Pastikan Java terinstall dan JAVA_HOME diset
2. Pastikan port 9092 dan 2181 tidak digunakan aplikasi lain
3. Cek log di direktori `logs/` Kafka

### Problem: Test gagal dengan connection refused
**Solusi**:
1. Pastikan Kafka server berjalan: `netstat -an | findstr :9092`
2. Cek firewall tidak memblokir port 9092
3. Tunggu beberapa detik setelah start Kafka sebelum menjalankan test

### Problem: Test timeout
**Solusi**:
1. Kurangi jumlah pesan untuk testing awal
2. Increase timeout di konfigurasi test
3. Cek resource sistem (CPU, Memory)

### Problem: Low throughput
**Solusi**:
1. Increase jumlah partisi topic
2. Tune konfigurasi producer (batch.size, linger.ms)
3. Increase concurrency worker

## 🎯 Contoh Output yang Diharapkan

```
=============================================================
📊 HASIL PENGUJIAN PERFORMA KAFKA - 10.000 PESAN
=============================================================
📤 PRODUKSI:
   • Total Pesan: 10000
   • Berhasil Dikirim: 10000
   • Gagal Dikirim: 0
   • Waktu Produksi: 45.234s
   • Throughput: 221.05 pesan/detik
   • Error Rate: 0.00%
   • Rata-rata Latency: 4.523ms

📥 KONSUMSI:
   • Total Dikonsumsi: 10000
   • Waktu Konsumsi: 12.456s
   • Throughput: 802.84 pesan/detik

🎯 RINGKASAN:
   • Success Rate: 100.00%
   • Consumption Rate: 100.00%
=============================================================
✅ Semua validasi performa berhasil!
```

## 📝 Tips Optimasi

1. **Untuk performa maksimal**:
   - Gunakan SSD untuk Kafka logs
   - Increase heap size JVM Kafka
   - Tune OS network parameters

2. **Untuk testing development**:
   - Kurangi replication factor ke 1
   - Gunakan compression (snappy/lz4)
   - Batch messages untuk efisiensi

3. **Monitoring real-time**:
   - Gunakan Kafka Manager atau AKHQ
   - Monitor JVM metrics
   - Track disk usage

## 🔗 Resources

- [Apache Kafka Documentation](https://kafka.apache.org/documentation/)
- [Kafka Performance Tuning](https://kafka.apache.org/documentation/#producerconfigs)
- [Java Download](https://adoptium.net/)
- [Kafka Downloads](https://kafka.apache.org/downloads)

---

**Happy Testing! 🚀**