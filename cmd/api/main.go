package main

import (
	"net/http"
	"os"

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

	// Create router
	router := mux.NewRouter()

	// Add a simple health check
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		log.WithFields(map[string]interface{}{
			"method":    r.Method,
			"path":      r.URL.Path,
			"remote_ip": r.RemoteAddr,
		}).Info("Health check requested")

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Auth Service is running"))
	}).Methods("GET")

	// Get port from environment or use default
	port := getEnv("PORT", "8081")

	log.WithField("port", port).Info("Auth service starting...")

	if err := http.ListenAndServe(":"+port, router); err != nil {
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
