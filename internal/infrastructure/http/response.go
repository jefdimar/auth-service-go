package http

import (
	"encoding/json"
	"net/http"
	"time"

	"auth-service-go/pkg/logger"
)

// Response represents a standard API response
type Response struct {
	Success   bool        `json:"success"`
	Data      interface{} `json:"data,omitempty"`
	Error     *ErrorInfo  `json:"error,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
}

// ErrorInfo represents error information
type ErrorInfo struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Type    string `json:"type,omitempty"`
}

// WriteJSON writes a JSON response
func WriteJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := Response{
		Success:   statusCode < 400,
		Data:      data,
		Timestamp: time.Now(),
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		logger.GetLogger().WithError(err).Error("Failed to encode JSON response")
	}
}

// WriteError writes an error response
func WriteError(w http.ResponseWriter, statusCode int, message string, errorType ...string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	errType := "error"
	if len(errorType) > 0 {
		errType = errorType[0]
	}

	response := Response{
		Success: false,
		Error: &ErrorInfo{
			Code:    statusCode,
			Message: message,
			Type:    errType,
		},
		Timestamp: time.Now(),
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		logger.GetLogger().WithError(err).Error("Failed to encode error response")
	}
}

// WriteValidationError writes a validation error response
func WriteValidationError(w http.ResponseWriter, message string) {
	WriteError(w, http.StatusBadRequest, message, "validation_error")
}

// WriteUnauthorizedError writes an unauthorized error response
func WriteUnauthorizedError(w http.ResponseWriter, message string) {
	WriteError(w, http.StatusUnauthorized, message, "unauthorized")
}

// WriteNotFoundError writes a not found error response
func WriteNotFoundError(w http.ResponseWriter, message string) {
	WriteError(w, http.StatusNotFound, message, "not_found")
}

// WriteInternalError writes an internal server error response
func WriteInternalError(w http.ResponseWriter, message string) {
	WriteError(w, http.StatusInternalServerError, message, "internal_error")
}
