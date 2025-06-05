package main

import (
	"net/http"
	"os"
	"strconv"
	"time"

	"auth-service-go/internal/application"
	"auth-service-go/internal/infrastructure/db"
	"auth-service-go/internal/infrastructure/http/handlers"
	"auth-service-go/internal/infrastructure/repositories"
	"auth-service-go/pkg/jwt"
	"auth-service-go/pkg/logger"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

func main() {
	// Initialize logger
	log := logger.GetLogger()
	log.Info("Starting auth service...")

	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Warn("Warning: .env file not found")
	}

	// Database configuration
	port, _ := strconv.Atoi(getEnv("DB_PORT", "5432"))
	dbConfig := db.Config{
		Host:     getEnv("DB_HOST", "localhost"),
		Port:     port,
		User:     getEnv("DB_USER", "postgres"),
		Password: getEnv("DB_PASSWORD", "postgres"),
		DBName:   getEnv("DB_NAME", "auth"),
		SSLMode:  getEnv("DB_SSLMODE", "disable"),
	}

	// Connect to database
	database, err := db.NewConnection(dbConfig)
	if err != nil {
		log.WithError(err).Fatal("Failed to connect to database")
	}
	defer database.Close()

	// Initialize database schema
	if err := db.CreateSchema(database); err != nil {
		log.WithError(err).Fatal("Failed to create database schema")
	}

	log.Info("Database initialized successfully")

	// Initialize repositories
	userRepo := repositories.NewPostgresUserRepository(database)

	// Initialize JWT manager
	jwtSecret := getEnv("JWT_SECRET", "your-super-secret-jwt-key-change-this-in-production")
	jwtExpiryHours, _ := strconv.Atoi(getEnv("JWT_EXPIRY_HOURS", "24"))
	jwtManager := jwt.NewJWTManager(jwtSecret, time.Duration(jwtExpiryHours)*time.Hour)

	// Initialize services
	authService := application.NewAuthService(userRepo, jwtManager)

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(authService)

	log.Info("Services and handlers initialized successfully")

	// Create router
	router := mux.NewRouter()

	// Health check routes
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		log.WithFields(map[string]interface{}{
			"method":    r.Method,
			"path":      r.URL.Path,
			"remote_ip": r.RemoteAddr,
		}).Info("Health check requested")

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Auth Service is running"))
	}).Methods("GET")

	router.HandleFunc("/health/db", func(w http.ResponseWriter, r *http.Request) {
		if err := database.Ping(); err != nil {
			log.WithError(err).Error("Database health check failed")
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("Database connection failed"))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Database connection OK"))
	}).Methods("GET")

	// API routes
	api := router.PathPrefix("/api/v1").Subrouter()

	// Authentication routes
	auth := api.PathPrefix("/auth").Subrouter()
	auth.HandleFunc("/register", authHandler.Register).Methods("POST")
	auth.HandleFunc("/login", authHandler.Login).Methods("POST")
	auth.HandleFunc("/refresh", authHandler.RefreshToken).Methods("POST")
	auth.HandleFunc("/logout", authHandler.Logout).Methods("POST")

	// User profile routes
	profile := api.PathPrefix("/profile").Subrouter()
	profile.HandleFunc("", authHandler.GetProfile).Methods("GET")
	profile.HandleFunc("", authHandler.UpdateProfile).Methods("PUT")

	// Add CORS middleware for development
	router.Use(corsMiddleware)

	// Add logging middleware
	router.Use(loggingMiddleware)

	// Get server port
	serverPort := getEnv("PORT", "8081")

	log.WithField("port", serverPort).Info("Auth service starting...")
	log.Info("Available endpoints:")
	log.Info("  GET  /health - Service health check")
	log.Info("  GET  /health/db - Database health check")
	log.Info("  POST /api/v1/auth/register - User registration")
	log.Info("  POST /api/v1/auth/login - User login")
	log.Info("  POST /api/v1/auth/refresh - Token refresh")
	log.Info("  POST /api/v1/auth/logout - User logout")
	log.Info("  GET  /api/v1/profile - Get user profile")
	log.Info("  PUT  /api/v1/profile - Update user profile")

	if err := http.ListenAndServe(":"+serverPort, router); err != nil {
		log.WithError(err).Fatal("Failed to start server")
	}
}

// corsMiddleware adds CORS headers for development
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs HTTP requests
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create a response writer wrapper to capture status code
		wrapper := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapper, r)

		logger.GetLogger().WithFields(map[string]interface{}{
			"method":      r.Method,
			"path":        r.URL.Path,
			"status_code": wrapper.statusCode,
			"duration_ms": time.Since(start).Milliseconds(),
			"remote_ip":   r.RemoteAddr,
			"user_agent":  r.UserAgent(),
		}).Info("HTTP request processed")
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// getEnv retrieves an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}
