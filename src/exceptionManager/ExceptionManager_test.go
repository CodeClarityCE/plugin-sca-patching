package exceptionManager

import (
	"testing"

	errorTypes "github.com/CodeClarityCE/utility-types/exceptions"
)

func TestAddPublicError(t *testing.T) {
	description := "mock description"
	errorType := errorTypes.ERROR_TYPE("mock error type")

	AddPublicError(description, errorType)

	// Verify that the public_errors slice contains the added public error
	if len(public_errors) != 1 {
		t.Errorf("Expected 1 public error, got %d", len(public_errors))
	}

	// Verify the description and error type of the added public error
	if public_errors[0].Description != description {
		t.Errorf("Expected description '%s', got '%s'", description, public_errors[0].Description)
	}
	if public_errors[0].Type != errorType {
		t.Errorf("Expected error type '%s', got '%s'", errorType, public_errors[0].Type)
	}
}

func TestAddPrivateError(t *testing.T) {
	description := "mock description"
	errorType := errorTypes.ERROR_TYPE("mock error type")

	AddPrivateError(description, errorType)

	// Verify that the private_errors slice contains the added private error
	if len(private_errors) != 1 {
		t.Errorf("Expected 1 private error, got %d", len(private_errors))
	}

	// Verify the description and error type of the added private error
	if private_errors[0].Description != description {
		t.Errorf("Expected description '%s', got '%s'", description, private_errors[0].Description)
	}
	if private_errors[0].Type != errorType {
		t.Errorf("Expected error type '%s', got '%s'", errorType, private_errors[0].Type)
	}
}

func TestGetPublicErrors(t *testing.T) {
	// Create a mock public error
	mockError := errorTypes.PublicError{
		Description: "mock description",
		Type:        errorTypes.ERROR_TYPE("mock error type"),
	}

	// Add the mock public error to the public_errors slice
	public_errors = append(public_errors, mockError)

	// Call the GetPublicErrors function
	result := GetPublicErrors()

	// Verify that the result contains the mock public error
	if len(result) != 2 {
		t.Errorf("Expected 2 public errors, got %d", len(result))
	}
	if result[0].Description != mockError.Description {
		t.Errorf("Expected description '%s', got '%s'", mockError.Description, result[0].Description)
	}
	if result[0].Type != mockError.Type {
		t.Errorf("Expected error type '%s', got '%s'", mockError.Type, result[0].Type)
	}
}

func TestGetPrivateErrors(t *testing.T) {
	// Create a mock private error
	mockError := errorTypes.PrivateError{
		Description: "mock description",
		Type:        errorTypes.ERROR_TYPE("mock error type"),
	}

	// Add the mock private error to the private_errors slice
	private_errors = append(private_errors, mockError)

	// Call the GetPrivateErrors function
	result := GetPrivateErrors()

	// Verify that the result contains the mock private error
	if len(result) != 2 {
		t.Errorf("Expected 2 private errors, got %d", len(result))
	}
	if result[0].Description != mockError.Description {
		t.Errorf("Expected description '%s', got '%s'", mockError.Description, result[0].Description)
	}
	if result[0].Type != mockError.Type {
		t.Errorf("Expected error type '%s', got '%s'", mockError.Type, result[0].Type)
	}
}
