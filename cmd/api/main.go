package main

import (
	"net/http"
	"os"
	"strconv"

	"auth-service-go/internal/infrastructure/db"
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

	// Create router
	router := mux.NewRouter()

	// Add health check
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		log.WithFields(map[string]interface{}{
			"method":    r.Method,
			"path":      r.URL.Path,
			"remote_ip": r.RemoteAddr,
		}).Info("Health check requested")

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Auth Service is running"))
	}).Methods("GET")

	// Add database health check
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

	// Get server port
	serverPort := getEnv("PORT", "8081")

	log.WithField("port", serverPort).Info("Auth service starting...")

	if err := http.ListenAndServe(":"+serverPort, router); err != nil {
		log.WithError(err).Fatal("Failed to start server")
	}
}

// getEnv retrieves an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}
