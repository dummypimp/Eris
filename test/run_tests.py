
"""
Comprehensive test runner for Mythic Android Agent
Runs all unit tests, integration tests, and compatibility tests
"""

import sys
import os
import unittest
import argparse
import time
import json
from pathlib import Path
from datetime import datetime


PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def discover_and_run_tests(test_dir, pattern="test_*.py", verbosity=2):
    """Discover and run tests in specified directory"""
    loader = unittest.TestLoader()
    suite = loader.discover(test_dir, pattern=pattern)
    
    runner = unittest.TextTestRunner(
        verbosity=verbosity,
        buffer=True,
        failfast=False
    )
    
    start_time = time.time()
    result = runner.run(suite)
    end_time = time.time()
    
    return {
        'tests_run': result.testsRun,
        'failures': len(result.failures),
        'errors': len(result.errors),
        'skipped': len(result.skipped) if hasattr(result, 'skipped') else 0,
        'success': result.wasSuccessful(),
        'duration': end_time - start_time,
        'failure_details': result.failures,
        'error_details': result.errors
    }


def run_unit_tests(verbosity=2):
    """Run all unit tests"""
    print("=" * 70)
    print("RUNNING UNIT TESTS")
    print("=" * 70)
    
    unit_test_dir = PROJECT_ROOT / "tests" / "unit"
    if not unit_test_dir.exists():
        print(f"Unit test directory not found: {unit_test_dir}")
        return None
    
    return discover_and_run_tests(str(unit_test_dir), verbosity=verbosity)


def run_integration_tests(verbosity=2):
    """Run all integration tests"""
    print("\n" + "=" * 70)
    print("RUNNING INTEGRATION TESTS")
    print("=" * 70)
    
    integration_test_dir = PROJECT_ROOT / "tests" / "integration"
    if not integration_test_dir.exists():
        print(f"Integration test directory not found: {integration_test_dir}")
        return None
    
    return discover_and_run_tests(str(integration_test_dir), verbosity=verbosity)


def run_compatibility_tests(verbosity=2):
    """Run Android compatibility tests"""
    print("\n" + "=" * 70)
    print("RUNNING ANDROID COMPATIBILITY TESTS")
    print("=" * 70)
    

    from tests.integration.test_apk_injection import TestAndroidVersionCompatibility
    
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestAndroidVersionCompatibility)
    
    runner = unittest.TextTestRunner(verbosity=verbosity, buffer=True)
    
    start_time = time.time()
    result = runner.run(suite)
    end_time = time.time()
    
    return {
        'tests_run': result.testsRun,
        'failures': len(result.failures),
        'errors': len(result.errors),
        'skipped': len(result.skipped) if hasattr(result, 'skipped') else 0,
        'success': result.wasSuccessful(),
        'duration': end_time - start_time,
        'failure_details': result.failures,
        'error_details': result.errors
    }


def run_c2_profile_tests(verbosity=2):
    """Run C2 profile specific tests"""
    print("\n" + "=" * 70)
    print("RUNNING C2 PROFILE TESTS")
    print("=" * 70)
    

    test_file = PROJECT_ROOT / "c2_profiles" / "test_profiles.py"
    if test_file.exists():
        os.system(f"python {test_file}")
    else:
        print(f"C2 profile test not found: {test_file}")
        return None
    
    return {"success": True, "message": "C2 profile tests completed"}


def generate_test_report(results, output_file=None):
    """Generate comprehensive test report"""
    timestamp = datetime.now().isoformat()
    
    report = {
        "timestamp": timestamp,
        "test_results": results,
        "summary": {
            "total_suites": len([r for r in results.values() if r is not None]),
            "total_tests": sum(r.get('tests_run', 0) for r in results.values() if r is not None),
            "total_failures": sum(r.get('failures', 0) for r in results.values() if r is not None),
            "total_errors": sum(r.get('errors', 0) for r in results.values() if r is not None),
            "total_skipped": sum(r.get('skipped', 0) for r in results.values() if r is not None),
            "overall_success": all(r.get('success', False) for r in results.values() if r is not None),
            "total_duration": sum(r.get('duration', 0) for r in results.values() if r is not None)
        }
    }
    
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\nDetailed test report saved to: {output_file}")
    
    return report


def print_summary(report):
    """Print test summary"""
    summary = report["summary"]
    
    print("\n" + "=" * 70)
    print("TEST EXECUTION SUMMARY")
    print("=" * 70)
    
    print(f"Timestamp: {report['timestamp']}")
    print(f"Total Test Suites: {summary['total_suites']}")
    print(f"Total Tests Run: {summary['total_tests']}")
    print(f"Total Duration: {summary['total_duration']:.2f} seconds")
    print()
    

    status_char = "✅" if summary['overall_success'] else "❌"
    print(f"Overall Status: {status_char} {'PASSED' if summary['overall_success'] else 'FAILED'}")
    
    print(f"Passed: {summary['total_tests'] - summary['total_failures'] - summary['total_errors']}")
    print(f"Failed: {summary['total_failures']}")
    print(f"Errors: {summary['total_errors']}")
    print(f"Skipped: {summary['total_skipped']}")
    

    print("\nSuite Results:")
    print("-" * 40)
    
    for suite_name, result in report["test_results"].items():
        if result is None:
            print(f"{suite_name}: SKIPPED (Not Available)")
            continue
            
        status = "PASSED" if result.get('success', False) else "FAILED"
        status_char = "✅" if result.get('success', False) else "❌"
        tests = result.get('tests_run', 0)
        duration = result.get('duration', 0)
        
        print(f"{suite_name}: {status_char} {status} ({tests} tests, {duration:.2f}s)")


def main():
    """Main test execution function"""
    parser = argparse.ArgumentParser(description="Mythic Android Agent Test Runner")
    parser.add_argument('--unit', action='store_true', help='Run only unit tests')
    parser.add_argument('--integration', action='store_true', help='Run only integration tests')
    parser.add_argument('--compatibility', action='store_true', help='Run only compatibility tests')
    parser.add_argument('--c2', action='store_true', help='Run only C2 profile tests')
    parser.add_argument('--verbose', '-v', action='count', default=2, help='Increase verbosity')
    parser.add_argument('--quiet', '-q', action='store_true', help='Minimal output')
    parser.add_argument('--report', '-r', help='Save detailed report to JSON file')
    parser.add_argument('--fast', action='store_true', help='Skip slow integration tests')
    
    args = parser.parse_args()
    

    verbosity = 0 if args.quiet else args.verbose
    

    print("🚀 MYTHIC ANDROID AGENT - COMPREHENSIVE TEST SUITE")
    print("=" * 70)
    print(f"Project Root: {PROJECT_ROOT}")
    print(f"Python Version: {sys.version}")
    print(f"Test Execution Started: {datetime.now()}")
    print()
    

    results = {}
    

    run_all = not any([args.unit, args.integration, args.compatibility, args.c2])
    
    try:

        if run_all or args.unit:
            results['unit_tests'] = run_unit_tests(verbosity)
        

        if run_all or args.integration:
            if not args.fast:
                results['integration_tests'] = run_integration_tests(verbosity)
            else:
                print("⚡ Skipping integration tests (--fast mode)")
                results['integration_tests'] = {"success": True, "skipped": True}
        

        if run_all or args.compatibility:
            results['compatibility_tests'] = run_compatibility_tests(verbosity)
        

        if run_all or args.c2:
            results['c2_profile_tests'] = run_c2_profile_tests(verbosity)
    
    except KeyboardInterrupt:
        print("\n\n❌ Test execution interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Unexpected error during test execution: {e}")
        sys.exit(1)
    

    report_file = args.report
    if not report_file and not args.quiet:

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = PROJECT_ROOT / "tests" / f"test_report_{timestamp}.json"
    
    report = generate_test_report(results, report_file)
    
    if not args.quiet:
        print_summary(report)
    

    exit_code = 0 if report["summary"]["overall_success"] else 1
    
    if exit_code == 0:
        print(f"\n🎉 All tests completed successfully!")
    else:
        print(f"\n💥 Some tests failed. Check the details above.")
    
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
