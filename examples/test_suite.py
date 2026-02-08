#!/usr/bin/env python3
"""
Bagman Test Suite (v2)

Runs all component tests and validates the full skill.
"""

import subprocess
import sys
from pathlib import Path


def run_test(name: str, module: str) -> bool:
    """Run a test module and return success status."""
    print(f"\n{'=' * 60}")
    print(f"Running: {name}")
    print('=' * 60)
    
    result = subprocess.run(
        [sys.executable, module],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent
    )
    
    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)
    
    # Check for failures in output
    if "FAIL" in result.stdout and "0 failed" not in result.stdout:
        print(f"❌ {name}: FAILED")
        return False
    
    if result.returncode != 0:
        print(f"❌ {name}: Exit code {result.returncode}")
        return False
    
    print(f"✅ {name}: PASSED")
    return True


def main():
    print("=" * 60)
    print("BAGMAN TEST SUITE v2")
    print("=" * 60)
    
    tests = [
        ("Output Sanitizer", "sanitizer.py"),
        ("Input Validator", "validator.py"),
    ]
    
    # Check for optional tests
    optional = Path(__file__).parent / "session_keys.py"
    if optional.exists():
        tests.append(("Session Keys", "session_keys.py"))
    
    optional = Path(__file__).parent / "secret_manager.py"
    if optional.exists():
        tests.append(("Secret Manager", "secret_manager.py"))
    
    results = []
    for name, module in tests:
        results.append((name, run_test(name, module)))
    
    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, ok in results if ok)
    failed = sum(1 for _, ok in results if not ok)
    
    for name, ok in results:
        status = "✅ PASS" if ok else "❌ FAIL"
        print(f"  {status}: {name}")
    
    print(f"\nTotal: {passed} passed, {failed} failed")
    
    if failed > 0:
        print("\n❌ TEST SUITE FAILED")
        sys.exit(1)
    else:
        print("\n✅ ALL TESTS PASSED")
        sys.exit(0)


if __name__ == "__main__":
    main()
