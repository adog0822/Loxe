"""
Configuration test script.
Verifies that all dependencies are installed and environment variables are loaded.
Does NOT print or log any credential values — only confirms presence/absence.
"""

import sys


def check_imports():
    """Verify all required packages can be imported."""
    packages = {
        "boto3": "boto3",
        "openai": "openai",
        "dotenv": "python-dotenv",
        "yaml": "pyyaml",
        "pandas": "pandas",
        "jinja2": "jinja2",
    }
    all_ok = True
    for module, pip_name in packages.items():
        try:
            __import__(module)
            print(f"  [OK] {pip_name}")
        except ImportError:
            print(f"  [FAIL] {pip_name} — run: pip install {pip_name}")
            all_ok = False
    return all_ok


def check_env_vars():
    """Verify environment variables are set (not placeholder values)."""
    from dotenv import load_dotenv
    import os

    load_dotenv()

    required_vars = {
        "OPENAI_API_KEY": "sk-your-openai-api-key-here",
        "AWS_ACCESS_KEY_ID": "your-aws-access-key-id-here",
        "AWS_SECRET_ACCESS_KEY": "your-aws-secret-access-key-here",
        "AWS_DEFAULT_REGION": None,  # any non-empty value is fine
    }

    all_ok = True
    for var, placeholder in required_vars.items():
        value = os.getenv(var, "")
        if not value:
            print(f"  [MISSING] {var} — not set")
            all_ok = False
        elif placeholder and value == placeholder:
            print(f"  [PLACEHOLDER] {var} — still has the template value, replace it with your real key")
            all_ok = False
        else:
            # Mask the value: show first 4 chars + asterisks
            masked = value[:4] + "*" * (len(value) - 4) if len(value) > 4 else "****"
            print(f"  [OK] {var} = {masked}")
    return all_ok


def check_gitignore():
    """Verify .env is protected by .gitignore."""
    import subprocess

    result = subprocess.run(
        ["git", "check-ignore", ".env"],
        capture_output=True, text=True, cwd="/home/user/Loxe"
    )
    if result.returncode == 0:
        print("  [OK] .env is listed in .gitignore")
        return True
    else:
        print("  [DANGER] .env is NOT gitignored — your credentials could be committed!")
        return False


def main():
    print("=" * 55)
    print("  Configuration & Security Test")
    print("=" * 55)

    print("\n1. Checking installed packages...")
    imports_ok = check_imports()

    print("\n2. Checking .gitignore security...")
    gitignore_ok = check_gitignore()

    print("\n3. Checking environment variables...")
    env_ok = check_env_vars()

    print("\n" + "=" * 55)
    if imports_ok and gitignore_ok and env_ok:
        print("  ALL CHECKS PASSED")
    else:
        if not imports_ok:
            print("  [!] Some packages are missing")
        if not gitignore_ok:
            print("  [!] .env is not protected by .gitignore")
        if not env_ok:
            print("  [!] Some credentials need to be configured")
            print("      Edit .env with your real keys, then re-run this script")
    print("=" * 55)

    return 0 if (imports_ok and gitignore_ok) else 1


if __name__ == "__main__":
    sys.exit(main())
