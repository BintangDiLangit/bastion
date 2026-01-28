// Package errors provides custom error types and utilities.
package errors

import (
	"errors"
	"fmt"
	"net/http"
)

// Error codes
const (
	CodeInternal      = "INTERNAL_ERROR"
	CodeNotFound      = "NOT_FOUND"
	CodeBadRequest    = "BAD_REQUEST"
	CodeUnauthorized  = "UNAUTHORIZED"
	CodeForbidden     = "FORBIDDEN"
	CodeConflict      = "CONFLICT"
	CodeRateLimit     = "RATE_LIMIT_EXCEEDED"
	CodeTimeout       = "TIMEOUT"
	CodeValidation    = "VALIDATION_ERROR"
	CodeDatabaseError = "DATABASE_ERROR"
)

// AppError represents an application error.
type AppError struct {
	Code       string            `json:"code"`
	Message    string            `json:"message"`
	Details    string            `json:"details,omitempty"`
	StatusCode int               `json:"-"`
	Err        error             `json:"-"`
	Meta       map[string]string `json:"meta,omitempty"`
}

// Error implements the error interface.
func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the wrapped error.
func (e *AppError) Unwrap() error {
	return e.Err
}

// WithDetails adds details to the error.
func (e *AppError) WithDetails(details string) *AppError {
	e.Details = details
	return e
}

// WithMeta adds metadata to the error.
func (e *AppError) WithMeta(key, value string) *AppError {
	if e.Meta == nil {
		e.Meta = make(map[string]string)
	}
	e.Meta[key] = value
	return e
}

// New creates a new AppError.
func New(code, message string, statusCode int) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		StatusCode: statusCode,
	}
}

// Wrap wraps an existing error.
func Wrap(err error, code, message string, statusCode int) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		StatusCode: statusCode,
		Err:        err,
	}
}

// Common errors

// ErrNotFound returns a not found error.
func ErrNotFound(resource string) *AppError {
	return &AppError{
		Code:       CodeNotFound,
		Message:    fmt.Sprintf("%s not found", resource),
		StatusCode: http.StatusNotFound,
	}
}

// ErrBadRequest returns a bad request error.
func ErrBadRequest(message string) *AppError {
	return &AppError{
		Code:       CodeBadRequest,
		Message:    message,
		StatusCode: http.StatusBadRequest,
	}
}

// ErrUnauthorized returns an unauthorized error.
func ErrUnauthorized(message string) *AppError {
	if message == "" {
		message = "Authentication required"
	}
	return &AppError{
		Code:       CodeUnauthorized,
		Message:    message,
		StatusCode: http.StatusUnauthorized,
	}
}

// ErrForbidden returns a forbidden error.
func ErrForbidden(message string) *AppError {
	if message == "" {
		message = "Access denied"
	}
	return &AppError{
		Code:       CodeForbidden,
		Message:    message,
		StatusCode: http.StatusForbidden,
	}
}

// ErrInternal returns an internal error.
func ErrInternal(err error) *AppError {
	return &AppError{
		Code:       CodeInternal,
		Message:    "Internal server error",
		StatusCode: http.StatusInternalServerError,
		Err:        err,
	}
}

// ErrValidation returns a validation error.
func ErrValidation(message string) *AppError {
	return &AppError{
		Code:       CodeValidation,
		Message:    message,
		StatusCode: http.StatusBadRequest,
	}
}

// ErrConflict returns a conflict error.
func ErrConflict(message string) *AppError {
	return &AppError{
		Code:       CodeConflict,
		Message:    message,
		StatusCode: http.StatusConflict,
	}
}

// ErrRateLimit returns a rate limit error.
func ErrRateLimit() *AppError {
	return &AppError{
		Code:       CodeRateLimit,
		Message:    "Rate limit exceeded",
		StatusCode: http.StatusTooManyRequests,
	}
}

// ErrTimeout returns a timeout error.
func ErrTimeout(message string) *AppError {
	if message == "" {
		message = "Request timeout"
	}
	return &AppError{
		Code:       CodeTimeout,
		Message:    message,
		StatusCode: http.StatusGatewayTimeout,
	}
}

// ErrDatabase returns a database error.
func ErrDatabase(err error) *AppError {
	return &AppError{
		Code:       CodeDatabaseError,
		Message:    "Database error",
		StatusCode: http.StatusInternalServerError,
		Err:        err,
	}
}

// IsAppError checks if an error is an AppError.
func IsAppError(err error) bool {
	var appErr *AppError
	return errors.As(err, &appErr)
}

// GetAppError extracts AppError from error.
func GetAppError(err error) *AppError {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr
	}
	return ErrInternal(err)
}

// Is checks if error matches target.
func Is(err, target error) bool {
	return errors.Is(err, target)
}

// As attempts to convert error to target type.
func As(err error, target interface{}) bool {
	return errors.As(err, target)
}

// Join combines multiple errors.
func Join(errs ...error) error {
	return errors.Join(errs...)
}
