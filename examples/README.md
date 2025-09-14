# Gawan Framework - Swagger Documentation Example

Contoh implementasi lengkap dokumentasi API menggunakan Swagger/OpenAPI dalam framework Gawan.

## 🚀 Fitur yang Didemonstrasikan

### ✅ Optimasi Performa
- **Caching System**: Redis dan In-Memory cache dengan multi-level caching
- **Connection Pooling**: Database connection pool yang dioptimasi
- **Performance Middleware**: Compression, rate limiting, dan HTTP caching

### ✅ Optimasi Skalabilitas
- **Load Balancing**: Multiple algorithms (round-robin, weighted, least connections, IP hash, random)
- **Clustering Support**: Node management, leader election, health checks
- **Service Discovery**: Automatic service registration dan health monitoring

### ✅ Dokumentasi API Lengkap
- **Swagger/OpenAPI 3.0**: Dokumentasi API yang komprehensif
- **Interactive UI**: Swagger UI yang dapat digunakan langsung
- **Auto-documentation**: Middleware untuk dokumentasi otomatis
- **Request/Response Examples**: Contoh lengkap untuk setiap endpoint
- **Authentication**: Dokumentasi Bearer Token dan API Key
- **Error Handling**: Dokumentasi pesan error yang detail

## 📋 Endpoint yang Tersedia

### User Management
- `GET /api/v1/users` - List semua users dengan pagination dan filtering
- `GET /api/v1/users/{id}` - Get user berdasarkan ID
- `POST /api/v1/users` - Buat user baru
- `PUT /api/v1/users/{id}` - Update user
- `DELETE /api/v1/users/{id}` - Hapus user

### System Information
- `GET /api/v1/health` - Health check komprehensif
- `GET /api/v1/version` - Informasi versi aplikasi

### Documentation
- `GET /docs/` - Swagger UI interface
- `GET /docs/swagger.json` - OpenAPI JSON specification

## 🛠️ Cara Menjalankan

### 1. Persiapan Environment

```bash
# Clone atau navigate ke project directory
cd C:\project\golang\tutorial

# Install dependencies (jika belum ada go.mod)
go mod init gawan-tutorial
go mod tidy
```

### 2. Jalankan Example Server

```bash
# Jalankan example server
go run examples/swagger_example.go
```

### 3. Akses Dokumentasi

Setelah server berjalan, buka browser dan akses:

- **Swagger UI**: http://localhost:8080/docs/
- **OpenAPI JSON**: http://localhost:8080/docs/swagger.json
- **API Base URL**: http://localhost:8080/api/v1

## 📖 Contoh Penggunaan API

### 1. List Users dengan Pagination

```bash
# Get semua users
curl http://localhost:8080/api/v1/users

# Get users dengan pagination
curl "http://localhost:8080/api/v1/users?page=1&limit=5"

# Filter users berdasarkan role
curl "http://localhost:8080/api/v1/users?role=admin"

# Filter users yang aktif
curl "http://localhost:8080/api/v1/users?active=true"

# Kombinasi filter dan sorting
curl "http://localhost:8080/api/v1/users?role=user&active=true&sort=created_at&order=desc"
```

### 2. Get User by ID

```bash
# Get user dengan ID 1
curl http://localhost:8080/api/v1/users/1
```

### 3. Create New User

```bash
# Buat user baru
curl -X POST http://localhost:8080/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{
    "username": "new_user",
    "email": "new.user@example.com",
    "full_name": "New User",
    "password": "SecurePassword123!",
    "role": "user"
  }'
```

### 4. Update User

```bash
# Update user dengan ID 2
curl -X PUT http://localhost:8080/api/v1/users/2 \
  -H "Content-Type: application/json" \
  -d '{
    "full_name": "John Updated Doe",
    "active": false
  }'
```

### 5. Delete User

```bash
# Hapus user dengan ID 3
curl -X DELETE http://localhost:8080/api/v1/users/3
```

### 6. Health Check

```bash
# Check system health
curl http://localhost:8080/api/v1/health
```

### 7. Version Information

```bash
# Get version info
curl http://localhost:8080/api/v1/version
```

## 📝 Response Format

Semua API endpoint menggunakan format response yang konsisten:

### Success Response
```json
{
  "success": true,
  "message": "Operation completed successfully",
  "data": {
    // Response data here
  }
}
```

### Error Response
```json
{
  "success": false,
  "message": "Error message",
  "error": {
    "code": 400,
    "message": "Detailed error message",
    "details": "Additional error information"
  }
}
```

## 🔐 Authentication & Authorization

Dokumentasi Swagger mencakup dua jenis autentikasi:

### 1. Bearer Token (JWT)
```bash
# Contoh penggunaan dengan Bearer token
curl -H "Authorization: Bearer your-jwt-token" \
     http://localhost:8080/api/v1/users
```

### 2. API Key
```bash
# Contoh penggunaan dengan API key
curl -H "X-API-Key: your-api-key" \
     http://localhost:8080/api/v1/users
```

## ⚠️ Error Codes

| Code | Message | Description |
|------|---------|-------------|
| 200 | OK | Request berhasil |
| 201 | Created | Resource berhasil dibuat |
| 400 | Bad Request | Request tidak valid |
| 401 | Unauthorized | Authentication diperlukan |
| 403 | Forbidden | Akses ditolak |
| 404 | Not Found | Resource tidak ditemukan |
| 409 | Conflict | Resource sudah ada |
| 422 | Unprocessable Entity | Validation error |
| 500 | Internal Server Error | Server error |

## 🎯 Fitur Swagger UI

### Interactive Testing
- **Try it out**: Test endpoint langsung dari UI
- **Request Builder**: Form builder untuk request body
- **Response Preview**: Preview response dengan syntax highlighting
- **Authentication**: Input untuk Bearer token dan API key

### Documentation Features
- **Detailed Descriptions**: Penjelasan lengkap untuk setiap endpoint
- **Parameter Documentation**: Dokumentasi parameter dengan validasi
- **Schema Definitions**: Model definitions dengan examples
- **Response Examples**: Contoh response untuk berbagai status code
- **Error Documentation**: Dokumentasi error yang mungkin terjadi

## 🔧 Kustomisasi

### Mengubah Konfigurasi Swagger

```go
// Dalam swagger_example.go
config := swagger.Config{
    Title:       "Your API Title",
    Description: "Your API Description",
    Version:     "2.0.0",
    Host:        "your-domain.com",
    BasePath:    "/api/v2",
    Schemes:     []string{"https"},
    Path:        "/documentation",
}
```

### Menambah Endpoint Baru

```go
// Dokumentasikan endpoint baru
op := swagger.CreateOperation(
    "Your Operation",
    "Description of your operation",
    []string{"YourTag"},
)

// Tambahkan parameter
op.AddParameter("param_name", "query", "Description", false, &swagger.Schema{
    Type: "string",
    Example: "example_value",
})

// Tambahkan response
op.AddResponse("200", "Success", &swagger.Schema{
    Type: "object",
    Properties: map[string]swagger.Schema{
        "result": {Type: "string", Example: "success"},
    },
})

// Daftarkan endpoint
swaggerMW.DocumentEndpoint("GET", "/api/v1/your-endpoint", nil, func(operation *swagger.Operation) {
    *operation = *op
})
```

## 📚 Struktur File

```
C:\project\golang\tutorial
├── internal/
│   ├── core/
│   │   ├── cache/           # Caching system (Redis, Memory, Multi-level)
│   │   ├── database/        # Database connection pooling
│   │   ├── middleware/      # Performance middleware
│   │   ├── loadbalancer/    # Load balancing algorithms
│   │   ├── cluster/         # Clustering support
│   │   ├── discovery/       # Service discovery
│   │   ├── metrics/         # Metrics and monitoring
│   │   └── swagger/         # Swagger/OpenAPI framework
│   └── ports/
│       ├── cache.go         # Cache interface
│       └── db.go           # Database interface
└── examples/
    ├── swagger_example.go   # Complete example implementation
    └── README.md           # This documentation
```

## 🚀 Production Deployment

### Environment Variables

```bash
# Server configuration
export PORT=8080
export HOST=0.0.0.0
export ENV=production

# Database configuration
export DB_HOST=localhost
export DB_PORT=5432
export DB_NAME=gawan_db
export DB_USER=gawan_user
export DB_PASSWORD=secure_password

# Redis configuration
export REDIS_HOST=localhost
export REDIS_PORT=6379
export REDIS_PASSWORD=redis_password

# API configuration
export API_VERSION=v1
export API_BASE_PATH=/api/v1

# Swagger configuration
export SWAGGER_ENABLED=true
export SWAGGER_PATH=/docs
export SWAGGER_TITLE="Your Production API"
```

### Docker Deployment

```dockerfile
# Dockerfile
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o main examples/swagger_example.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/main .
EXPOSE 8080
CMD ["./main"]
```

```bash
# Build dan run dengan Docker
docker build -t gawan-api .
docker run -p 8080:8080 gawan-api
```

## 🤝 Contributing

Untuk berkontribusi pada pengembangan framework Gawan:

1. Fork repository
2. Buat feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push ke branch (`git push origin feature/amazing-feature`)
5. Buat Pull Request

## 📄 License

Framework Gawan dilisensikan di bawah MIT License. Lihat file LICENSE untuk detail lengkap.

## 🆘 Support

Jika Anda mengalami masalah atau memiliki pertanyaan:

1. Periksa dokumentasi Swagger di `/docs/`
2. Lihat contoh penggunaan di file ini
3. Buat issue di repository GitHub
4. Hubungi tim development

---

**Happy Coding! 🎉**

Framework Gawan - Powerful, Scalable, Well-Documented