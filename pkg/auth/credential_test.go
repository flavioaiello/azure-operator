package auth

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnforceSecretlessArchitectureClean(t *testing.T) {
	// Ensure no forbidden env vars are set.
	for _, envVar := range ForbiddenCredentialEnvVars {
		os.Unsetenv(envVar)
	}

	err := EnforceSecretlessArchitecture()
	assert.NoError(t, err)
}

func TestEnforceSecretlessArchitectureClientSecret(t *testing.T) {
	os.Setenv("AZURE_CLIENT_SECRET", "super-secret-value")
	defer os.Unsetenv("AZURE_CLIENT_SECRET")

	err := EnforceSecretlessArchitecture()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSecretlessViolation)
	assert.Contains(t, err.Error(), "AZURE_CLIENT_SECRET")
}

func TestEnforceSecretlessArchitectureCertificatePath(t *testing.T) {
	os.Setenv("AZURE_CLIENT_CERTIFICATE_PATH", "/path/to/cert.pem")
	defer os.Unsetenv("AZURE_CLIENT_CERTIFICATE_PATH")

	err := EnforceSecretlessArchitecture()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSecretlessViolation)
	assert.Contains(t, err.Error(), "AZURE_CLIENT_CERTIFICATE_PATH")
}

func TestEnforceSecretlessArchitecturePassword(t *testing.T) {
	os.Setenv("AZURE_PASSWORD", "password123")
	defer os.Unsetenv("AZURE_PASSWORD")

	err := EnforceSecretlessArchitecture()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSecretlessViolation)
	assert.Contains(t, err.Error(), "AZURE_PASSWORD")
}

func TestEnforceSecretlessArchitectureUsername(t *testing.T) {
	os.Setenv("AZURE_USERNAME", "user@example.com")
	defer os.Unsetenv("AZURE_USERNAME")

	err := EnforceSecretlessArchitecture()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSecretlessViolation)
	assert.Contains(t, err.Error(), "AZURE_USERNAME")
}

func TestEnforceSecretlessArchitectureAllForbiddenVars(t *testing.T) {
	// Test each forbidden variable individually.
	for _, envVar := range ForbiddenCredentialEnvVars {
		t.Run(envVar, func(t *testing.T) {
			// Clear all first.
			for _, v := range ForbiddenCredentialEnvVars {
				os.Unsetenv(v)
			}

			// Set the one we're testing.
			os.Setenv(envVar, "some-value")
			defer os.Unsetenv(envVar)

			err := EnforceSecretlessArchitecture()
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrSecretlessViolation)
			assert.Contains(t, err.Error(), envVar)
		})
	}
}

func TestMaskClientID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"12345678-1234-1234-1234-123456789012", "12345678..."},
		{"short", "****"},
		{"12345678", "****"},
		{"123456789", "12345678..."},
		{"", "****"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, maskClientID(tt.input))
		})
	}
}

func TestForbiddenCredentialEnvVarsComplete(t *testing.T) {
	// Verify all expected forbidden variables are in the list.
	expected := map[string]bool{
		"AZURE_CLIENT_SECRET":               true,
		"AZURE_CLIENT_CERTIFICATE_PATH":     true,
		"AZURE_CLIENT_CERTIFICATE_PASSWORD": true,
		"AZURE_USERNAME":                    true,
		"AZURE_PASSWORD":                    true,
	}

	for _, envVar := range ForbiddenCredentialEnvVars {
		assert.True(t, expected[envVar], "Unexpected forbidden var: %s", envVar)
		delete(expected, envVar)
	}

	assert.Empty(t, expected, "Missing forbidden vars: %v", expected)
}
