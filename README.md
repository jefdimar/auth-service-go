# Auth Service Go

A comprehensive authentication and authorization service built with Go, featuring JWT tokens, role-based access control (RBAC), and PostgreSQL integration.

## 🚀 Features

- **User Authentication**: Registration, login, logout, token refresh
- **Role-Based Access Control (RBAC)**: Admin, Manager, User, Viewer roles
- **JWT Token Management**: Secure token generation and validation
- **User Profile Management**: Update profile information
- **Admin User Management**: Complete CRUD operations for user management
- **PostgreSQL Integration**: Robust database operations
- **Comprehensive Logging**: Structured logging with different levels
- **Middleware Protection**: Authentication and authorization middleware
- **Health Checks**: Service and database health endpoints

## 🏗️ Architecture

```
cmd/
├── api/
│   └── main.go                 # Application entry point
internal/
├── application/
│   ├── auth_service.go         # Core authentication logic
│   └── auth_service_admin.go   # Admin operations
├── domain/
│   ├── user.go                 # User entity and role definitions
│   ├── user_repository.go      # Repository interface
│   └── errors.go               # Domain errors
├── infrastructure/
│   ├── db/
│   │   ├── connection.go       # Database connection
│   │   └── schema.go           # Database schema
│   ├── http/
│   │   ├── handlers/           # HTTP handlers
│   │   └── utils.go            # HTTP utilities
│   └── repositories/
│       └── postgres_user_repository.go
├── middleware/
│   └── auth_middleware.go      # Authentication middleware
pkg/
├── jwt/
│   └── jwt_manager.go          # JWT token management
└── logger/
    └── logger.go               # Logging utilities
```

## 🔐 Role-Based Access Control

### Roles Hierarchy

- **Admin**: Full system access, can manage all users
- **Manager**: Can view users and statistics (read-only)
- **User**: Standard user access, can manage own profile
- **Viewer**: Read-only access to own profile

### Permission Matrix

| Endpoint                   | Public | User | Manager | Admin |
| -------------------------- | ------ | ---- | ------- | ----- |
| `POST /auth/register`      | ✅     | ✅   | ✅      | ✅    |
| `POST /auth/login`         | ✅     | ✅   | ✅      | ✅    |
| `GET /profile`             | ❌     | ✅   | ✅      | ✅    |
| `PUT /profile`             | ❌     | ✅   | ✅      | ✅    |
| `GET /manager/users`       | ❌     | ❌   | ✅      | ✅    |
| `GET /admin/users`         | ❌     | ❌   | ❌      | ✅    |
| `PUT /admin/users/{id}`    | ❌     | ❌   | ❌      | ✅    |
| `DELETE /admin/users/{id}` | ❌     | ❌   | ❌      | ✅    |

## 🛠️ Setup

### Prerequisites

- Go 1.21+
- PostgreSQL 12+
- Git

### Installation

1. **Clone the repository:**

```bash
git clone <repository-url>
cd auth-service-go
```

2. **Install dependencies:**

```bash
go mod download
```

3. **Set up environment variables:**

```bash
cp .env.example .env
# Edit .env with your configuration
```

4. **Set up PostgreSQL database:**

```sql
CREATE DATABASE auth;
CREATE USER auth_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE auth TO auth_user;
```

5. **Run the application:**

```bash
go run cmd/api/main.go
```

## 📚 API Documentation

### Authentication Endpoints

#### Register User

```http
POST /api/v1/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123",
  "first_name": "John",
  "last_name": "Doe",
  "role": "user"
}
```

#### Login

```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}
```

#### Get Profile (Protected)

```http
GET /api/v1/profile
Authorization: Bearer <jwt_token>
```

### Admin Endpoints (Admin Only)

#### List Users

```http
GET /api/v1/admin/users?offset=0&limit=10
Authorization: Bearer <admin_jwt_token>
```

#### Update User

```http
PUT /api/v1/admin/users/{user_id}
Authorization: Bearer <admin_jwt_token>
Content-Type: application/json

{
  "first_name": "Updated Name",
  "role": "manager",
  "is_active": true
}
```

#### Get User Statistics

```http
GET /api/v1/admin/stats
Authorization: Bearer <admin_jwt_token>
```

## 🧪 Testing

### Manual Testing Examples

1. **Create an admin user:**

```bash
curl -X POST http://localhost:8081/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "password": "password123",
    "first_name": "Admin",
    "last_name": "User",
    "role": "admin"
  }'
```

2. **Login and get token:**

```bash
curl -X POST http://localhost:8081/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "password": "password123"
  }'
```

3. **Access protected endpoints:**

```bash
curl -X GET http://localhost:8081/api/v1/admin/users \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

## 🔧 Configuration

### Environment Variables

| Variable           | Description        | Default     |
| ------------------ | ------------------ | ----------- |
| `DB_HOST`          | Database host      | `localhost` |
| `DB_PORT`          | Database port      | `5432`      |
| `DB_USER`          | Database user      | `postgres`  |
| `DB_PASSWORD`      | Database password  | `postgres`  |
| `DB_NAME`          | Database name      | `auth`      |
| `JWT_SECRET`       | JWT signing secret | Required    |
| `JWT_EXPIRY_HOURS` | Token expiry time  | `24`        |
| `PORT`             | Server port        | `8081`      |

## 🚀 Deployment

### Docker Deployment (Coming in Step 6)

- Docker containerization
- Docker Compose setup
- Production configuration

### Production Considerations

- Use strong JWT secrets
- Enable HTTPS
- Configure proper CORS settings
- Set up database connection pooling
- Implement rate limiting
- Add request validation
- Set up monitoring and logging

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License.
