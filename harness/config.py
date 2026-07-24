import os
from pathlib import Path

# Paths — relative to the sast-skills repo root (one level up from harness/)
ROOT_DIR   = Path(__file__).parent.parent
SKILLS_DIR = ROOT_DIR / ".claude" / "commands"
SCRIPTS_DIR = ROOT_DIR / "harness" / "scripts"  # deterministic (non-LLM) step scripts
REPOS_DIR  = ROOT_DIR / "sast-repos"    # cloned target repos live here
RUNS_DIR   = ROOT_DIR / "sast-runs"     # run artifacts live here

# Anthropic
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
MODEL = os.environ.get("SAST_MODEL", "claude-sonnet-4-6")
MAX_SKILL_ITERATIONS = int(os.environ.get("MAX_SKILL_ITERATIONS", "60"))

# Auth — single user, configure via environment variables
HARNESS_USERNAME = os.environ.get("HARNESS_USERNAME", "admin")
HARNESS_PASSWORD = os.environ.get("HARNESS_PASSWORD", "changeme")  # set this in production
JWT_SECRET       = os.environ.get("JWT_SECRET", "change-this-jwt-secret-in-production")
JWT_ALGORITHM    = "HS256"
JWT_EXPIRE_HOURS = int(os.environ.get("JWT_EXPIRE_HOURS", "24"))

# Server
HOST = os.environ.get("HARNESS_HOST", "0.0.0.0")
PORT = int(os.environ.get("HARNESS_PORT", "8000"))
