// Package auth provides security enforcement for secretless architecture.
//
// This module enforces the secretless security model where:
//   - ALL operators use User-Assigned Managed Identities (UAMIs)
//   - NO service principal secrets are allowed
//   - NO credentials are stored in environment variables or files
//
// SECURITY INVARIANTS:
//  1. AZURE_CLIENT_SECRET must never be present in the environment
//  2. ManagedIdentityCredential is the ONLY allowed credential type
//  3. All authentication flows through Entra ID
package auth

import (
	"errors"
	"fmt"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"go.uber.org/zap"
)

// ForbiddenCredentialEnvVars lists environment variables that indicate credential leakage.
// SECURITY: These must NEVER be present in the operator environment.
var ForbiddenCredentialEnvVars = []string{
	"AZURE_CLIENT_SECRET",
	"AZURE_CLIENT_CERTIFICATE_PATH",
	"AZURE_CLIENT_CERTIFICATE_PASSWORD",
	"AZURE_USERNAME",
	"AZURE_PASSWORD",
}

// ErrSecretlessViolation indicates secretless architecture is violated.
var ErrSecretlessViolation = errors.New("secretless architecture violation")

// SecretlessViolationMessage is the formatted error message for security violations.
const SecretlessViolationMessage = `
╔══════════════════════════════════════════════════════════════════════════════╗
║                         SECURITY VIOLATION DETECTED                          ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  This operator enforces a SECRETLESS architecture using Managed Identity.    ║
║                                                                               ║
║  Detected: %s
║                                                                               ║
║  This environment variable indicates service principal or password-based     ║
║  authentication, which is NOT ALLOWED.                                        ║
║                                                                               ║
║  RESOLUTION:                                                                  ║
║  1. Remove all credential environment variables                              ║
║  2. Assign a User-Assigned Managed Identity (UAMI) to this container         ║
║  3. Grant the UAMI appropriate RBAC roles on target resources                ║
║                                                                               ║
║  See: https://learn.microsoft.com/azure/active-directory/managed-identities  ║
╚══════════════════════════════════════════════════════════════════════════════╝
`

// EnforceSecretlessArchitecture checks that no credential secrets are present.
//
// This MUST be called at operator startup before any Azure SDK usage.
// Failure to call this function before using Azure credentials is a security bug.
func EnforceSecretlessArchitecture() error {
	for _, envVar := range ForbiddenCredentialEnvVars {
		if os.Getenv(envVar) != "" {
			zap.L().Error("Secretless architecture violation",
				zap.String("security_event", "credential_detected"),
				zap.String("env_var", envVar),
				zap.String("action", "startup_blocked"),
			)
			return fmt.Errorf("%w: %s detected - %s",
				ErrSecretlessViolation,
				envVar,
				fmt.Sprintf(SecretlessViolationMessage, envVar))
		}
	}

	zap.L().Info("Secretless architecture verified",
		zap.String("security_event", "secretless_verified"),
		zap.String("credential_type", "ManagedIdentity"),
	)

	return nil
}

// GetManagedIdentityCredential returns a ManagedIdentityCredential after verification.
//
// This is the ONLY way to obtain credentials in this codebase.
// Using any other credential type is a security violation.
//
// Parameters:
//   - clientID: Optional client ID for user-assigned managed identity.
//     If empty, uses system-assigned managed identity.
//
// Returns:
//   - TokenCredential for Azure SDK authentication.
//   - Error if secretless architecture is violated.
func GetManagedIdentityCredential(clientID string) (azcore.TokenCredential, error) {
	// SECURITY: Always enforce secretless before returning credentials.
	if err := EnforceSecretlessArchitecture(); err != nil {
		return nil, err
	}

	opts := &azidentity.ManagedIdentityCredentialOptions{}

	if clientID != "" {
		opts.ID = azidentity.ClientID(clientID)
		zap.L().Info("Using user-assigned managed identity",
			zap.String("client_id", maskClientID(clientID)),
		)
	} else {
		zap.L().Info("Using system-assigned managed identity")
	}

	cred, err := azidentity.NewManagedIdentityCredential(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create managed identity credential: %w", err)
	}

	return cred, nil
}

// maskClientID masks a client ID for logging.
func maskClientID(id string) string {
	if len(id) <= 8 {
		return "****"
	}
	return id[:8] + "..."
}

// LogSecurityAuditEvent logs a security-relevant audit event.
//
// All security events are logged with structured data for SIEM ingestion.
func LogSecurityAuditEvent(eventType, operatorName, targetResource, action, result string) {
	zap.L().Info("Security audit event",
		zap.Bool("security_audit", true),
		zap.String("event_type", eventType),
		zap.String("operator", operatorName),
		zap.String("target_resource", targetResource),
		zap.String("action", action),
		zap.String("result", result),
	)
}
