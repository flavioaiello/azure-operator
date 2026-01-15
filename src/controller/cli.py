"""Azure Operator CLI (azo).

Replaces Makefile with a Pythonic CLI for development, build, and deployment operations.

Usage:
    azo dev test          # Run tests
    azo dev lint          # Lint code
    azo dev fmt           # Format code
    azo build image       # Build Docker image
    azo deploy infra      # Deploy infrastructure
    azo run management    # Run operator locally
    azo clean             # Clean build artifacts
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import click

# CLI constants with documented bounds
DEFAULT_ACR_NAME = "cralzoperators"
DEFAULT_IMAGE_TAG = "latest"
IMAGE_NAME = "azure-operator"
DOMAINS = ("management", "connectivity", "policy", "security", "identity")

# Directory constants
TESTS_DIR = "tests/"
SRC_DIR = "src/"
MAIN_BICEP_FILENAME = "main.bicep"

# Timeout constants (seconds)
COMMAND_TIMEOUT_SECONDS = 300
BUILD_TIMEOUT_SECONDS = 600


def get_project_root() -> Path:
    """Get the project root directory.

    Returns:
        Path to project root (where pyproject.toml lives).
    """
    # Walk up from current file to find pyproject.toml
    current = Path(__file__).resolve()
    for parent in [current, *current.parents]:
        if (parent / "pyproject.toml").exists():
            return parent
    # Fallback to current working directory
    return Path.cwd()


def get_venv_path() -> Path:
    """Get the virtual environment path."""
    return get_project_root() / ".venv"


def get_venv_bin(name: str) -> Path:
    """Get path to a binary in the virtual environment."""
    return get_venv_path() / "bin" / name


def run_command(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int = COMMAND_TIMEOUT_SECONDS,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run a command with proper error handling.

    Args:
        cmd: Command and arguments.
        cwd: Working directory.
        env: Environment variables (merged with current env).
        timeout: Command timeout in seconds.
        capture: Whether to capture output instead of streaming.

    Returns:
        CompletedProcess result.

    Raises:
        click.ClickException: If command fails.
    """
    full_env = os.environ.copy()
    if env:
        full_env.update(env)

    try:
        result = subprocess.run(
            cmd,
            cwd=cwd or get_project_root(),
            env=full_env,
            timeout=timeout,
            capture_output=capture,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            if capture and result.stderr:
                raise click.ClickException(f"Command failed: {result.stderr}")
            raise click.ClickException(f"Command failed with exit code {result.returncode}")
        return result
    except subprocess.TimeoutExpired as e:
        raise click.ClickException(f"Command timed out after {timeout}s: {' '.join(cmd)}") from e
    except FileNotFoundError as e:
        raise click.ClickException(f"Command not found: {cmd[0]}") from e


def ensure_venv() -> None:
    """Ensure virtual environment exists and is activated."""
    venv_path = get_venv_path()
    if not venv_path.exists():
        raise click.ClickException(
            f"Virtual environment not found at {venv_path}. Run 'azo dev setup' first."
        )


def check_az_cli() -> None:
    """Check that Azure CLI is installed."""
    if not shutil.which("az"):
        raise click.ClickException(
            "Azure CLI (az) not found. Install from https://aka.ms/installazurecliwindows"
        )


def check_docker() -> None:
    """Check that Docker is installed and running."""
    if not shutil.which("docker"):
        raise click.ClickException(
            "Docker not found. Install Docker Desktop from https://docker.com"
        )
    # Check Docker daemon is running
    result = subprocess.run(
        ["docker", "info"],
        capture_output=True,
        timeout=10,
        check=False,
    )
    if result.returncode != 0:
        raise click.ClickException("Docker daemon is not running. Start Docker Desktop.")


# =============================================================================
# Main CLI Group
# =============================================================================


@click.group()
@click.version_option(version="0.1.0", prog_name="azo")
def cli() -> None:
    """Azure Operator CLI (azo).

    Development, build, and deployment tool for Azure Landing Zone Operator.

    \b
    Quick Start:
        azo dev setup      # Set up development environment
        azo dev test       # Run tests
        azo run bootstrap  # Run bootstrap operator locally
    """
    pass


# =============================================================================
# Development Commands
# =============================================================================


@cli.group()
def dev() -> None:
    """Development commands: setup, test, lint, format, typecheck."""
    pass


@dev.command()
def setup() -> None:
    """Create virtual environment and install dependencies."""
    root = get_project_root()
    venv_path = get_venv_path()

    click.echo(f"Creating virtual environment at {venv_path}...")
    run_command([sys.executable, "-m", "venv", str(venv_path)], cwd=root)

    pip = str(get_venv_bin("pip"))
    click.echo("Upgrading pip...")
    run_command([pip, "install", "--upgrade", "pip"], cwd=root)

    click.echo("Installing development dependencies...")
    run_command([pip, "install", "-r", "requirements-dev.txt"], cwd=root)

    click.echo("Installing package in editable mode...")
    run_command([pip, "install", "-e", "."], cwd=root)

    click.secho("✓ Development environment ready!", fg="green")
    click.echo(f"  Activate with: source {venv_path}/bin/activate")


@dev.command()
@click.option("--coverage", "-c", is_flag=True, help="Generate HTML coverage report")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option("--filter", "-k", "filter_expr", help="Run tests matching expression")
def test(coverage: bool, verbose: bool, filter_expr: str | None) -> None:
    """Run tests with pytest."""
    ensure_venv()
    pytest = str(get_venv_bin("pytest"))

    cmd = [pytest, TESTS_DIR]
    if verbose:
        cmd.append("-v")
    if coverage:
        cmd.extend(["--cov=src/controller", "--cov-report=html", "--cov-report=term-missing"])
    else:
        cmd.extend(["--cov=src/controller", "--cov-report=term-missing"])
    if filter_expr:
        cmd.extend(["-k", filter_expr])

    run_command(cmd)
    if coverage:
        click.echo("\n📊 Coverage report: htmlcov/index.html")


@dev.command()
@click.option("--fix", "-f", is_flag=True, help="Auto-fix linting issues")
def lint(fix: bool) -> None:
    """Lint Python code with ruff."""
    ensure_venv()
    ruff = str(get_venv_bin("ruff"))

    click.echo("Checking Python code...")
    cmd = [ruff, "check", SRC_DIR, TESTS_DIR]
    if fix:
        cmd.append("--fix")
    run_command(cmd)

    click.echo("\nChecking formatting...")
    run_command([ruff, "format", "--check", SRC_DIR, TESTS_DIR])

    click.secho("✓ All lint checks passed!", fg="green")


@dev.command()
def fmt() -> None:
    """Format Python code with ruff."""
    ensure_venv()
    ruff = str(get_venv_bin("ruff"))

    click.echo("Formatting code...")
    run_command([ruff, "format", SRC_DIR, TESTS_DIR])
    run_command([ruff, "check", "--fix", SRC_DIR, TESTS_DIR])
    click.secho("✓ Code formatted!", fg="green")


@dev.command()
def typecheck() -> None:
    """Run mypy type checking."""
    ensure_venv()
    mypy = str(get_venv_bin("mypy"))

    click.echo("Running type checks...")
    run_command([mypy, "src/controller/"])
    click.secho("✓ Type checks passed!", fg="green")


@dev.command("lint-bicep")
def lint_bicep() -> None:
    """Lint Bicep files with Azure CLI."""
    check_az_cli()
    root = get_project_root()
    bicep_dir = root / "bicep"

    if not bicep_dir.exists():
        raise click.ClickException(f"Bicep directory not found: {bicep_dir}")

    click.echo("Linting Bicep files...")
    domains_checked = 0

    for domain_dir in bicep_dir.iterdir():
        if domain_dir.is_dir():
            main_bicep = domain_dir / MAIN_BICEP_FILENAME
            if main_bicep.exists():
                click.echo(f"  {domain_dir.name}...")
                run_command(
                    ["az", "bicep", "build", "--file", str(main_bicep), "--stdout"],
                    capture=True,
                )
                domains_checked += 1

    click.secho(f"✓ {domains_checked} Bicep modules validated!", fg="green")


# =============================================================================
# Build Commands
# =============================================================================


@cli.group()
def build() -> None:
    """Build commands: image, git-sync, templates."""
    pass


@build.command("image")
@click.option("--acr", "acr_name", default=DEFAULT_ACR_NAME, help="ACR name")
@click.option("--tag", "image_tag", default=DEFAULT_IMAGE_TAG, help="Image tag")
@click.option("--no-cache", is_flag=True, help="Build without cache")
def build_image(acr_name: str, image_tag: str, no_cache: bool) -> None:
    """Build the operator Docker image."""
    check_docker()
    root = get_project_root()

    image = f"{acr_name}.azurecr.io/{IMAGE_NAME}:{image_tag}"
    click.echo(f"Building {image}...")

    cmd = ["docker", "build", "-t", image, "-f", "build/Dockerfile", "."]
    if no_cache:
        cmd.insert(2, "--no-cache")

    run_command(cmd, cwd=root, timeout=BUILD_TIMEOUT_SECONDS)
    click.secho(f"✓ Built {image}", fg="green")


@build.command("git-sync")
@click.option("--acr", "acr_name", default=DEFAULT_ACR_NAME, help="ACR name")
@click.option("--tag", "image_tag", default=DEFAULT_IMAGE_TAG, help="Image tag")
def build_git_sync(acr_name: str, image_tag: str) -> None:
    """Build the git-sync sidecar image."""
    check_docker()
    root = get_project_root()

    image = f"{acr_name}.azurecr.io/git-sync:{image_tag}"
    click.echo(f"Building {image}...")

    run_command(
        ["docker", "build", "-t", image, "-f", "build/Dockerfile.git-sync", "build/"],
        cwd=root,
        timeout=BUILD_TIMEOUT_SECONDS,
    )
    click.secho(f"✓ Built {image}", fg="green")


@build.command("all")
@click.option("--acr", "acr_name", default=DEFAULT_ACR_NAME, help="ACR name")
@click.option("--tag", "image_tag", default=DEFAULT_IMAGE_TAG, help="Image tag")
@click.pass_context
def build_all(ctx: click.Context, acr_name: str, image_tag: str) -> None:
    """Build all Docker images."""
    ctx.invoke(build_image, acr_name=acr_name, image_tag=image_tag)
    ctx.invoke(build_git_sync, acr_name=acr_name, image_tag=image_tag)


@build.command("templates")
def build_templates() -> None:
    """Compile Bicep to ARM JSON templates."""
    check_az_cli()
    root = get_project_root()
    bicep_dir = root / "bicep"
    templates_dir = root / "templates"

    templates_dir.mkdir(exist_ok=True)
    click.echo(f"Compiling Bicep templates to {templates_dir}...")

    compiled = 0
    for domain in DOMAINS:
        main_bicep = bicep_dir / domain / MAIN_BICEP_FILENAME
        if main_bicep.exists():
            output = templates_dir / f"{domain}.json"
            click.echo(f"  {domain} → {output.name}")
            run_command(
                ["az", "bicep", "build", "--file", str(main_bicep), "--outfile", str(output)],
            )
            compiled += 1

    click.secho(f"✓ Compiled {compiled} templates!", fg="green")


# =============================================================================
# Push Commands
# =============================================================================


@cli.group()
def push() -> None:
    """Push images to Azure Container Registry."""
    pass


@push.command("login")
@click.option("--acr", "acr_name", default=DEFAULT_ACR_NAME, help="ACR name")
def push_login(acr_name: str) -> None:
    """Login to Azure Container Registry."""
    check_az_cli()
    click.echo(f"Logging into {acr_name}.azurecr.io...")
    run_command(["az", "acr", "login", "--name", acr_name])
    click.secho("✓ Logged in!", fg="green")


@push.command("image")
@click.option("--acr", "acr_name", default=DEFAULT_ACR_NAME, help="ACR name")
@click.option("--tag", "image_tag", default=DEFAULT_IMAGE_TAG, help="Image tag")
@click.pass_context
def push_image(ctx: click.Context, acr_name: str, image_tag: str) -> None:
    """Push operator image to ACR."""
    check_docker()
    ctx.invoke(push_login, acr_name=acr_name)
    ctx.invoke(build_image, acr_name=acr_name, image_tag=image_tag)

    image = f"{acr_name}.azurecr.io/{IMAGE_NAME}:{image_tag}"
    click.echo(f"Pushing {image}...")
    run_command(["docker", "push", image])
    click.secho(f"✓ Pushed {image}", fg="green")


@push.command("all")
@click.option("--acr", "acr_name", default=DEFAULT_ACR_NAME, help="ACR name")
@click.option("--tag", "image_tag", default=DEFAULT_IMAGE_TAG, help="Image tag")
@click.pass_context
def push_all(ctx: click.Context, acr_name: str, image_tag: str) -> None:
    """Push all images to ACR."""
    ctx.invoke(push_image, acr_name=acr_name, image_tag=image_tag)
    ctx.invoke(push_login, acr_name=acr_name)

    git_sync_image = f"{acr_name}.azurecr.io/git-sync:{image_tag}"
    ctx.invoke(build_git_sync, acr_name=acr_name, image_tag=image_tag)
    click.echo(f"Pushing {git_sync_image}...")
    run_command(["docker", "push", git_sync_image])
    click.secho(f"✓ Pushed {git_sync_image}", fg="green")


# =============================================================================
# Run Commands
# =============================================================================


@cli.command()
@click.argument("domain", type=click.Choice([*DOMAINS, "bootstrap"]))
@click.option("--subscription", "-s", envvar="AZURE_SUBSCRIPTION_ID", help="Azure subscription ID")
@click.option("--location", "-l", default="westeurope", help="Azure location")
@click.option(
    "--specs-dir", type=click.Path(exists=True), default="./specs", help="Specs directory"
)
@click.option("--dry-run/--no-dry-run", default=True, help="Dry run mode (default: true)")
@click.option(
    "--scope", type=click.Choice(["subscription", "managementGroup"]), default="subscription"
)
def run(
    domain: str,
    subscription: str | None,
    location: str,
    specs_dir: str,
    dry_run: bool,
    scope: str,
) -> None:
    """Run operator locally for a specific domain.

    \b
    Examples:
        azo run bootstrap --subscription <id>
        azo run management --dry-run
        azo run connectivity --no-dry-run
    """
    ensure_venv()

    # Compile templates first
    check_az_cli()
    root = get_project_root()
    templates_dir = root / "templates"

    if not templates_dir.exists() or not list(templates_dir.glob("*.json")):
        click.echo("Compiling Bicep templates first...")

        ctx = click.Context(build_templates)
        ctx.invoke(build_templates)

    if not subscription:
        raise click.ClickException(
            "Azure subscription ID required. Set AZURE_SUBSCRIPTION_ID or use --subscription."
        )

    click.echo(f"Running {domain} operator locally...")
    click.echo(f"  Subscription: {subscription}")
    click.echo(f"  Location: {location}")
    click.echo(f"  Scope: {scope}")
    click.echo(f"  Dry run: {dry_run}")

    env = {
        "DOMAIN": domain,
        "DEPLOYMENT_SCOPE": scope,
        "AZURE_SUBSCRIPTION_ID": subscription,
        "AZURE_LOCATION": location,
        "TEMPLATES_DIR": str(templates_dir),
        "SPECS_DIR": str(Path(specs_dir).resolve()),
        "DRY_RUN": "true" if dry_run else "false",
    }

    python = str(get_venv_bin("python"))
    run_command([python, "-m", "controller.main"], env=env, timeout=0)


# =============================================================================
# Deploy Commands
# =============================================================================


@cli.group()
def deploy() -> None:
    """Deploy infrastructure to Azure."""
    pass


@deploy.command("infra")
@click.option("--location", "-l", default="westeurope", help="Azure location")
def deploy_infra(location: str) -> None:
    """Deploy operator infrastructure to Azure."""
    check_az_cli()
    root = get_project_root()

    click.echo(f"Deploying infrastructure to {location}...")
    run_command(
        [
            "az",
            "deployment",
            "sub",
            "create",
            "--location",
            location,
            "--template-file",
            str(root / "infrastructure" / MAIN_BICEP_FILENAME),
            "--parameters",
            str(root / "infrastructure" / "main.bicepparam"),
        ],
        timeout=BUILD_TIMEOUT_SECONDS,
    )
    click.secho("✓ Infrastructure deployed!", fg="green")


@deploy.command("rbac")
@click.option("--management-group", "-m", "mgmt_group", envvar="MGMT_GROUP_ID", required=True)
@click.option("--location", "-l", default="westeurope", help="Azure location")
def deploy_rbac(mgmt_group: str, location: str) -> None:
    """Deploy RBAC assignments (requires Owner at management group)."""
    check_az_cli()
    root = get_project_root()

    click.echo(f"Deploying RBAC to management group {mgmt_group}...")
    run_command(
        [
            "az",
            "deployment",
            "mg",
            "create",
            "--location",
            location,
            "--management-group-id",
            mgmt_group,
            "--template-file",
            str(root / "infrastructure" / "rbac.bicep"),
            "--parameters",
            str(root / "infrastructure" / "rbac.bicepparam"),
        ],
        timeout=BUILD_TIMEOUT_SECONDS,
    )
    click.secho("✓ RBAC deployed!", fg="green")


# =============================================================================
# Clean Command
# =============================================================================


@cli.command()
@click.option("--all", "-a", "clean_all", is_flag=True, help="Also remove venv and Docker images")
@click.option("--acr", "acr_name", default=DEFAULT_ACR_NAME, help="ACR name for image cleanup")
@click.option("--tag", "image_tag", default=DEFAULT_IMAGE_TAG, help="Image tag for cleanup")
def clean(clean_all: bool, acr_name: str, image_tag: str) -> None:
    """Clean build artifacts and caches."""
    root = get_project_root()
    removed = []

    # Always remove these
    to_remove = [
        root / "templates",
        root / ".pytest_cache",
        root / ".mypy_cache",
        root / ".ruff_cache",
        root / "htmlcov",
    ]

    # Remove egg-info directories
    for egg_info in root.glob("*.egg-info"):
        to_remove.append(egg_info)
    for egg_info in (root / "src").glob("*.egg-info"):
        to_remove.append(egg_info)

    # Find all __pycache__ directories
    for pycache in root.rglob("__pycache__"):
        to_remove.append(pycache)

    if clean_all:
        to_remove.append(root / ".venv")

    for path in to_remove:
        if path.exists():
            click.echo(f"Removing {path.relative_to(root)}...")
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
            removed.append(path.name)

    # Clean Docker images
    if clean_all and shutil.which("docker"):
        for image in [
            f"{acr_name}.azurecr.io/{IMAGE_NAME}:{image_tag}",
            f"{acr_name}.azurecr.io/git-sync:{image_tag}",
        ]:
            result = subprocess.run(
                ["docker", "rmi", "-f", image],
                capture_output=True,
                check=False,
            )
            if result.returncode == 0:
                removed.append(image)

    if removed:
        click.secho(f"✓ Cleaned {len(removed)} items", fg="green")
    else:
        click.echo("Nothing to clean")


# =============================================================================
# Info Command
# =============================================================================


@cli.command()
def info() -> None:
    """Show project and environment information."""
    root = get_project_root()
    venv_path = get_venv_path()

    click.echo("Azure Operator (azo)")
    click.echo("=" * 40)
    click.echo(f"Project root: {root}")
    click.echo(f"Virtual env:  {venv_path} {'✓' if venv_path.exists() else '✗'}")

    # Check tools
    click.echo("\nTools:")
    for tool, cmd in [
        ("Python", [sys.executable, "--version"]),
        ("Docker", ["docker", "--version"]),
        ("Azure CLI", ["az", "--version"]),
    ]:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False)
            version = (
                result.stdout.split("\n")[0].strip() if result.returncode == 0 else "not found"
            )
            click.echo(f"  {tool}: {version}")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            click.echo(f"  {tool}: not found")

    # Show domains
    click.echo(f"\nDomains: {', '.join(DOMAINS)}")


# =============================================================================
# Entry Point
# =============================================================================


def main() -> None:
    """Entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()
