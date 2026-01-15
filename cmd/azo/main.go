// Package main implements the azo CLI tool.
//
// azo provides development, build, and deployment commands:
//
//	azo dev test          # Run tests
//	azo dev lint          # Lint code
//	azo build image       # Build Docker image
//	azo deploy infra      # Deploy infrastructure
//	azo run management    # Run operator locally
//	azo clean             # Clean build artifacts
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	// Version is set at build time.
	version = "dev"

	// Logger for CLI.
	logger *zap.Logger
)

// CLI constants for flag defaults.
const (
	defaultOperatorPath = "./cmd/operator"
	defaultSpecsDir     = "./archetypes/1-multi-region-hub-spoke-azfw/specs"
	defaultTemplatesDir = "./templates"
	flagSpecsDir        = "specs-dir"
	flagTemplatesDir    = "templates-dir"
	descSpecsDir        = "Specs directory"
	descTemplatesDir    = "Templates directory"
)

func main() {
	// Initialize logger.
	logger, _ = zap.NewDevelopment()
	defer func() {
		_ = logger.Sync()
	}()

	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "azo",
		Short: "Azure Operator CLI",
		Long: `azo is the CLI for the Azure Landing Zone Operator.

It provides commands for development, building, testing, and running
the operator locally or deploying to Azure.`,
		Version:      version,
		SilenceUsage: true,
	}

	// Add subcommands.
	cmd.AddCommand(
		newDevCmd(),
		newBuildCmd(),
		newRunCmd(),
		newDeployCmd(),
		newDriftCmd(),
		newApprovalCmd(),
		newPauseCmd(),
		newBootstrapCmd(),
		newMigrateCmd(),
		newValidateCmd(),
		newCleanCmd(),
	)

	return cmd
}

func newDevCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dev",
		Short: "Development commands",
	}

	cmd.AddCommand(
		&cobra.Command{
			Use:   "test",
			Short: "Run tests",
			RunE: func(cmd *cobra.Command, args []string) error {
				return runCommand("go", "test", "-race", "-cover", "./...")
			},
		},
		&cobra.Command{
			Use:   "lint",
			Short: "Lint code",
			RunE: func(cmd *cobra.Command, args []string) error {
				return runCommand("golangci-lint", "run", "./...")
			},
		},
		&cobra.Command{
			Use:   "fmt",
			Short: "Format code",
			RunE: func(cmd *cobra.Command, args []string) error {
				if err := runCommand("gofmt", "-w", "."); err != nil {
					return err
				}
				return runCommand("goimports", "-w", ".")
			},
		},
	)

	return cmd
}

func newBuildCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "build",
		Short: "Build commands",
	}

	var (
		registry string
		tag      string
	)

	imageCmd := &cobra.Command{
		Use:   "image",
		Short: "Build Docker image",
		RunE: func(cmd *cobra.Command, args []string) error {
			imageName := registry + "/azure-operator:" + tag
			return runCommand("docker", "build",
				"-t", imageName,
				"-f", "build/Dockerfile.go",
				".",
			)
		},
	}
	imageCmd.Flags().StringVarP(&registry, "registry", "r", "cralzoperators.azurecr.io", "Container registry")
	imageCmd.Flags().StringVarP(&tag, "tag", "t", "latest", "Image tag")

	binaryCmd := &cobra.Command{
		Use:   "binary",
		Short: "Build operator binary",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCommand("go", "build",
				"-ldflags", "-s -w",
				"-o", "bin/operator",
				defaultOperatorPath,
			)
		},
	}

	cmd.AddCommand(imageCmd, binaryCmd)

	return cmd
}

func newRunCmd() *cobra.Command {
	var (
		specsDir     string
		templatesDir string
		mode         string
	)

	cmd := &cobra.Command{
		Use:   "run [domain]",
		Short: "Run operator locally",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			logger.Info("Running operator",
				zap.String("domain", domain),
				zap.String("mode", mode),
			)

			// Set environment variables for local run.
			os.Setenv("DOMAIN", domain)
			os.Setenv("SPECS_DIR", specsDir)
			os.Setenv("TEMPLATES_DIR", templatesDir)
			os.Setenv("RECONCILIATION_MODE", mode)

			return runCommand("go", "run", defaultOperatorPath)
		},
	}

	cmd.Flags().StringVar(&specsDir, flagSpecsDir, defaultSpecsDir, descSpecsDir)
	cmd.Flags().StringVar(&templatesDir, flagTemplatesDir, defaultTemplatesDir, descTemplatesDir)
	cmd.Flags().StringVar(&mode, "mode", "observe", "Reconciliation mode (observe|enforce|protect)")

	return cmd
}

func newDeployCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "deploy",
		Short: "Deployment commands",
	}

	var (
		location       string
		subscriptionID string
	)

	infraCmd := &cobra.Command{
		Use:   "infra",
		Short: "Deploy infrastructure",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCommand("az", "deployment", "sub", "create",
				"--location", location,
				"--template-file", "infrastructure/main.bicep",
				"--subscription", subscriptionID,
			)
		},
	}
	infraCmd.Flags().StringVar(&location, "location", "westeurope", "Azure location")
	infraCmd.Flags().StringVar(&subscriptionID, "subscription", "", "Azure subscription ID")
	_ = infraCmd.MarkFlagRequired("subscription")

	cmd.AddCommand(infraCmd)

	return cmd
}

func newCleanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "clean",
		Short: "Clean build artifacts",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCommand("rm", "-rf", "bin/", "dist/")
		},
	}
}

func newDriftCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "drift",
		Short: "Drift detection commands",
	}

	var (
		specsDir     string
		templatesDir string
		domain       string
		output       string
	)

	showCmd := &cobra.Command{
		Use:   "show",
		Short: "Show drift for a domain",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.Info("Detecting drift",
				zap.String("domain", domain),
				zap.String("output", output),
			)

			os.Setenv("DOMAIN", domain)
			os.Setenv("SPECS_DIR", specsDir)
			os.Setenv("TEMPLATES_DIR", templatesDir)
			os.Setenv("RECONCILIATION_MODE", "observe")

			return runCommand("go", "run", defaultOperatorPath, "--once")
		},
	}
	showCmd.Flags().StringVar(&domain, "domain", "", "Domain to check")
	showCmd.Flags().StringVar(&specsDir, flagSpecsDir, defaultSpecsDir, descSpecsDir)
	showCmd.Flags().StringVar(&templatesDir, flagTemplatesDir, defaultTemplatesDir, descTemplatesDir)
	showCmd.Flags().StringVar(&output, "output", "table", "Output format (table|json|yaml)")
	_ = showCmd.MarkFlagRequired("domain")

	applyCmd := &cobra.Command{
		Use:   "apply",
		Short: "Apply detected drift",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.Info("Applying drift",
				zap.String("domain", domain),
			)

			os.Setenv("DOMAIN", domain)
			os.Setenv("SPECS_DIR", specsDir)
			os.Setenv("TEMPLATES_DIR", templatesDir)
			os.Setenv("RECONCILIATION_MODE", "enforce")

			return runCommand("go", "run", defaultOperatorPath, "--once")
		},
	}
	applyCmd.Flags().StringVar(&domain, "domain", "", "Domain to apply")
	applyCmd.Flags().StringVar(&specsDir, flagSpecsDir, defaultSpecsDir, descSpecsDir)
	applyCmd.Flags().StringVar(&templatesDir, flagTemplatesDir, defaultTemplatesDir, descTemplatesDir)
	_ = applyCmd.MarkFlagRequired("domain")

	cmd.AddCommand(showCmd, applyCmd)

	return cmd
}

func newApprovalCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "approval",
		Short: "Approval workflow commands",
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List pending approvals",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.Info("Listing pending approvals")
			logger.Warn("approval listing not yet implemented")
			return nil
		},
	}

	var approvalID string

	approveCmd := &cobra.Command{
		Use:   "approve",
		Short: "Approve a pending deployment",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.Info("Approving deployment",
				zap.String("id", approvalID),
			)
			logger.Warn("approval not yet implemented")
			return nil
		},
	}
	approveCmd.Flags().StringVar(&approvalID, "id", "", "Approval ID")
	_ = approveCmd.MarkFlagRequired("id")

	rejectCmd := &cobra.Command{
		Use:   "reject",
		Short: "Reject a pending deployment",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.Info("Rejecting deployment",
				zap.String("id", approvalID),
			)
			logger.Warn("rejection not yet implemented")
			return nil
		},
	}
	rejectCmd.Flags().StringVar(&approvalID, "id", "", "Approval ID")
	_ = rejectCmd.MarkFlagRequired("id")

	cmd.AddCommand(listCmd, approveCmd, rejectCmd)

	return cmd
}

func runCommand(name string, args ...string) error {
	cmd := NewExecCommand(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func newPauseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pause",
		Short: "Pause/resume operator reconciliation",
	}

	var operatorName, reason, message string

	pauseCmd := &cobra.Command{
		Use:   "set",
		Short: "Pause an operator",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.Info("Pausing operator",
				zap.String("operator", operatorName),
				zap.String("reason", reason),
			)
			logger.Warn("pause not yet implemented")
			return nil
		},
	}
	pauseCmd.Flags().StringVar(&operatorName, "operator", "", "Operator name")
	pauseCmd.Flags().StringVar(&reason, "reason", "manual", "Pause reason")
	pauseCmd.Flags().StringVar(&message, "message", "", "Pause message")
	_ = pauseCmd.MarkFlagRequired("operator")

	resumeCmd := &cobra.Command{
		Use:   "resume",
		Short: "Resume a paused operator",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.Info("Resuming operator",
				zap.String("operator", operatorName),
			)
			logger.Warn("resume not yet implemented")
			return nil
		},
	}
	resumeCmd.Flags().StringVar(&operatorName, "operator", "", "Operator name")
	_ = resumeCmd.MarkFlagRequired("operator")

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show pause status for operators",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.Info("Checking pause status")
			logger.Warn("status check not yet implemented")
			return nil
		},
	}

	cmd.AddCommand(pauseCmd, resumeCmd, statusCmd)

	return cmd
}

func newBootstrapCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bootstrap",
		Short: "Bootstrap operator infrastructure",
	}

	var dryRun bool
	var configFile string

	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize bootstrap configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.Info("Initializing bootstrap configuration")
			logger.Warn("bootstrap init not yet implemented")
			return nil
		},
	}

	provisionCmd := &cobra.Command{
		Use:   "provision",
		Short: "Provision operator identities and RBAC",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.Info("Provisioning operator infrastructure",
				zap.Bool("dryRun", dryRun),
				zap.String("config", configFile),
			)
			logger.Warn("bootstrap not yet implemented")
			return nil
		},
	}
	provisionCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be provisioned")
	provisionCmd.Flags().StringVar(&configFile, "config", "bootstrap.yaml", "Bootstrap config file")

	verifyCmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify operator identities and RBAC",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.Info("Verifying operator infrastructure")
			logger.Warn("bootstrap verify not yet implemented")
			return nil
		},
	}

	cmd.AddCommand(initCmd, provisionCmd, verifyCmd)

	return cmd
}

func newMigrateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Migration commands for Python to Go transition",
	}

	var operator string
	var resultsDir string

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show migration status for all operators",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.Info("Migration status",
				zap.String("operator", operator),
			)
			logger.Warn("migrate not yet implemented")
			return nil
		},
	}
	statusCmd.Flags().StringVar(&operator, "operator", "", "Filter by operator")

	promoteCmd := &cobra.Command{
		Use:   "promote",
		Short: "Promote operator to next migration stage",
		RunE: func(cmd *cobra.Command, args []string) error {
			if operator == "" {
				return fmt.Errorf("--operator is required")
			}
			logger.Info("Promoting operator",
				zap.String("operator", operator),
			)
			logger.Warn("migrate not yet implemented")
			return nil
		},
	}
	promoteCmd.Flags().StringVar(&operator, "operator", "", "Operator to promote")
	_ = promoteCmd.MarkFlagRequired("operator")

	rollbackCmd := &cobra.Command{
		Use:   "rollback",
		Short: "Rollback operator to previous migration stage",
		RunE: func(cmd *cobra.Command, args []string) error {
			if operator == "" {
				return fmt.Errorf("--operator is required")
			}
			logger.Info("Rolling back operator",
				zap.String("operator", operator),
			)
			logger.Warn("migrate not yet implemented")
			return nil
		},
	}
	rollbackCmd.Flags().StringVar(&operator, "operator", "", "Operator to rollback")
	_ = rollbackCmd.MarkFlagRequired("operator")

	compareCmd := &cobra.Command{
		Use:   "compare",
		Short: "Compare Python and Go results",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.Info("Comparing results",
				zap.String("operator", operator),
				zap.String("resultsDir", resultsDir),
			)
			logger.Warn("migrate not yet implemented")
			return nil
		},
	}
	compareCmd.Flags().StringVar(&operator, "operator", "", "Operator to compare")
	compareCmd.Flags().StringVar(&resultsDir, "results-dir", "/var/lib/azure-operator/results", "Results directory")

	cmd.AddCommand(statusCmd, promoteCmd, rollbackCmd, compareCmd)

	return cmd
}

func newValidateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate specs and templates",
	}

	var specsDir string
	var templatesDir string

	specsCmd := &cobra.Command{
		Use:   "specs",
		Short: "Validate spec files",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.Info("Validating specs",
				zap.String("dir", specsDir),
			)
			logger.Warn("validation not yet implemented")
			return nil
		},
	}
	specsCmd.Flags().StringVar(&specsDir, "dir", "specs", "Specs directory")

	templatesCmd := &cobra.Command{
		Use:   "templates",
		Short: "Validate template files",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.Info("Validating templates",
				zap.String("dir", templatesDir),
			)
			logger.Warn("validation not yet implemented")
			return nil
		},
	}
	templatesCmd.Flags().StringVar(&templatesDir, "dir", "bicep", "Templates directory")

	compareCmd := &cobra.Command{
		Use:   "compare [dir1] [dir2]",
		Short: "Compare specs between directories",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.Info("Comparing specs",
				zap.String("dir1", args[0]),
				zap.String("dir2", args[1]),
			)
			logger.Warn("validation not yet implemented")
			return nil
		},
	}

	cmd.AddCommand(specsCmd, templatesCmd, compareCmd)

	return cmd
}
