package exceptionManager

import (
	errorTypes "github.com/CodeClarityCE/utility-types/exceptions"
)

var public_errors []errorTypes.PublicError = []errorTypes.PublicError{}
var private_errors []errorTypes.PrivateError = []errorTypes.PrivateError{}

// AddPublicError adds a public error to the list of public errors.
// It takes a description string and an error type as parameters.
// The description parameter specifies the description of the error.
// The error_type parameter specifies the type of the error.
func AddPublicError(description string, error_type errorTypes.ERROR_TYPE) {
	public_error := errorTypes.PublicError{}
	public_error.Description = description
	public_error.Type = error_type
	public_errors = append(public_errors, public_error)
}

// AddPrivateError adds a private error to the exception manager.
// It takes a description string and an error type as parameters.
// The private error is created with the given description and type,
// and then appended to the list of private errors.
func AddPrivateError(description string, error_type errorTypes.ERROR_TYPE) {
	private_error := errorTypes.PrivateError{}
	private_error.Description = description
	private_error.Type = error_type
	private_errors = append(private_errors, private_error)
}

// GetPublicErrors returns a slice of public errors.
func GetPublicErrors() []errorTypes.PublicError {
	return public_errors
}

// GetPrivateErrors returns a slice of private errors.
// It retrieves the private_errors variable from the ExceptionManager package.
func GetPrivateErrors() []errorTypes.PrivateError {
	return private_errors
}
