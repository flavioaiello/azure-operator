// Package main is the entry point for the Azure Controller.
//
// The controller runs a continuous reconciliation loop that:
// 1. Loads desired state from specs via SpecLoader interface
// 2. Detects drift using Resource Graph (fast-path) and ARM WhatIf (precise)
// 3. Applies changes based on reconciliation mode (observe/enforce/protect)
//
// SECURITY: Enforces secretless architecture - Managed Identity only.
//
// NOTE: This is a library/framework entrypoint. Domain-specific operators
// (e.g., azure-operator, sentinel-operator) should provide their own main.go
// that injects a concrete SpecLoader implementation.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/flavioaiello/azure-operator/pkg/auth"
	"github.com/flavioaiello/azure-operator/pkg/config"
	"github.com/flavioaiello/azure-operator/pkg/reconciler"
)

// This main exists for standalone testing. In production, domain-specific
// operators embed this controller and provide their own SpecLoader.
func main() {
	logger := initLogger()
	defer func() {
		_ = logger.Sync()
	}()

	zap.ReplaceGlobals(logger)

	logger.Info("Starting Azure Controller",
		zap.String("version", version()),
	)

	cfg, err := config.LoadFromEnv()
	if err != nil {
		logger.Fatal("Failed to load configuration",
			zap.Error(err),
		)
	}

	logger.Info("Configuration loaded",
		zap.String("domain", cfg.Domain),
		zap.String("subscription_id", maskSubscriptionID(cfg.SubscriptionID)),
		zap.String("location", cfg.Location),
		zap.String("mode", string(cfg.Mode)),
		zap.Duration("reconcile_interval", cfg.ReconcileInterval),
	)

	if err := auth.EnforceSecretlessArchitecture(); err != nil {
		logger.Fatal("Secretless architecture violation",
			zap.Error(err),
		)
	}

	clientID := os.Getenv("AZURE_CLIENT_ID")
	cred, err := auth.GetManagedIdentityCredential(clientID)
	if err != nil {
		logger.Fatal("Failed to get managed identity credential",
			zap.Error(err),
		)
	}

	// NoopLoader for standalone mode - real operators inject their loader.
	loader := &noopLoader{}

	rec, err := reconciler.New(cfg, cred, logger, loader)
	if err != nil {
		logger.Fatal("Failed to create reconciler",
			zap.Error(err),
		)
	}

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGTERM,
		syscall.SIGINT,
	)
	defer cancel()

	logger.Info("Starting reconciliation loop")
	if err := rec.Run(ctx); err != nil && err != context.Canceled {
		logger.Fatal("Reconciler failed",
			zap.Error(err),
		)
	}

	logger.Info("Controller shutdown complete")
}

// noopLoader is a placeholder SpecLoader for standalone controller mode.
type noopLoader struct{}

func (n *noopLoader) LoadSpec(domain string) (reconciler.Spec, error) {
	return nil, fmt.Errorf("no spec loader configured for domain %q - inject a concrete loader", domain)
}

func (n *noopLoader) LoadTemplate(domain string) (map[string]interface{}, error) {
	return nil, fmt.Errorf("no template loader configured for domain %q - inject a concrete loader", domain)
}

func initLogger() *zap.Logger {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder

	config := zap.Config{
		Level:            zap.NewAtomicLevelAt(zap.InfoLevel),
		Development:      false,
		Encoding:         "json",
		EncoderConfig:    encoderConfig,
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}

	logger, err := config.Build()
	if err != nil {
		return zap.NewNop()
	}

	return logger
}

func version() string {
	return "dev"
}

func maskSubscriptionID(id string) string {
	if len(id) < 8 {
		return "****"
	}
	return id[:8] + "-****-****-****-************"
}
