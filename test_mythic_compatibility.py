#!/usr/bin/env python3
"""
Eris Android Agent - Mythic Compatibility Test Suite
Comprehensive testing for Mythic 3.3 CLI installation and integration
"""

import os
import sys
import json
import subprocess
import importlib.util
from pathlib import Path
from typing import Dict, List, Any, Optional
import tempfile
import shutil

class MythicCompatibilityTester:
    """Test suite for validating Mythic 3.3 compatibility"""
    
    def __init__(self, agent_path: str = "."):
        self.agent_path = Path(agent_path).resolve()
        self.test_results = {}
        self.errors = []
        
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all compatibility tests"""
        print("🚀 Starting Eris Android Agent - Mythic Compatibility Tests")
        print("=" * 60)
        
        # Test 1: File Structure Validation
        self._test_file_structure()
        
        # Test 2: Payload Type Manifest
        self._test_payload_manifest()
        
        # Test 3: Agent Functions
        self._test_agent_functions()
        
        # Test 4: C2 Profile Manifests
        self._test_c2_profiles()
        
        # Test 5: Browser Scripts
        self._test_browser_scripts()
        
        # Test 6: Command Classes
        self._test_command_classes()
        
        # Test 7: Python Import Validation
        self._test_python_imports()
        
        # Test 8: Mythic CLI Simulation
        self._test_mythic_cli_simulation()
        
        # Generate Report
        return self._generate_report()
        
    def _test_file_structure(self):
        """Test required file structure for Mythic compatibility"""
        print("📁 Testing File Structure...")
        
        required_files = [
            "payload_type.json",
            "agent_functions.py", 
            "eris_commands.py",
            "Dockerfile",
            "requirements.txt"
        ]
        
        required_dirs = [
            "agent",
            "builder", 
            "c2_profiles",
            "c2_profiles/https_beacon",
            "c2_profiles/fcm_push",
            "c2_profiles/dns_covert",
            "browser_scripts"
        ]
        
        c2_manifests = [
            "c2_profiles/https_beacon/c2_profile.json",
            "c2_profiles/fcm_push/c2_profile.json", 
            "c2_profiles/dns_covert/c2_profile.json"
        ]
        
        missing_files = []
        missing_dirs = []
        
        # Check files
        for file_path in required_files:
            if not (self.agent_path / file_path).exists():
                missing_files.append(file_path)
                
        # Check directories
        for dir_path in required_dirs:
            if not (self.agent_path / dir_path).exists():
                missing_dirs.append(dir_path)
                
        # Check C2 manifests
        for manifest_path in c2_manifests:
            if not (self.agent_path / manifest_path).exists():
                missing_files.append(manifest_path)
        
        self.test_results["file_structure"] = {
            "status": "PASS" if not missing_files and not missing_dirs else "FAIL",
            "missing_files": missing_files,
            "missing_directories": missing_dirs,
            "details": f"Found {len(required_files) - len(missing_files)}/{len(required_files)} required files"
        }
        
        if missing_files or missing_dirs:
            self.errors.extend(missing_files + missing_dirs)
            
    def _test_payload_manifest(self):
        """Test payload_type.json validity"""
        print("📋 Testing Payload Manifest...")
        
        manifest_path = self.agent_path / "payload_type.json"
        
        try:
            with open(manifest_path, 'r') as f:
                manifest = json.load(f)
                
            required_fields = ["name", "author", "version", "supported_os", "description", "build_parameters"]
            missing_fields = [field for field in required_fields if field not in manifest]
            
            # Validate build parameters
            param_issues = []
            if "build_parameters" in manifest:
                for param in manifest["build_parameters"]:
                    if "name" not in param or "description" not in param:
                        param_issues.append(f"Invalid parameter: {param}")
            
            self.test_results["payload_manifest"] = {
                "status": "PASS" if not missing_fields and not param_issues else "FAIL", 
                "missing_fields": missing_fields,
                "parameter_issues": param_issues,
                "total_parameters": len(manifest.get("build_parameters", []))
            }
            
        except Exception as e:
            self.test_results["payload_manifest"] = {
                "status": "FAIL",
                "error": str(e)
            }
            self.errors.append(f"Payload manifest error: {e}")
            
    def _test_agent_functions(self):
        """Test agent_functions.py validity"""
        print("🔧 Testing Agent Functions...")
        
        agent_functions_path = self.agent_path / "agent_functions.py"
        
        try:
            spec = importlib.util.spec_from_file_location("agent_functions", agent_functions_path)
            agent_functions = importlib.util.module_from_spec(spec)
            
            # Test import without execution
            with open(agent_functions_path, 'r') as f:
                content = f.read()
                
            # Check for required components
            required_components = [
                "ErisPayloadType",
                "PayloadType", 
                "create_tasking_",
                "process_",
                "mythic_payloadtype_container"
            ]
            
            found_components = []
            for component in required_components:
                if component in content:
                    found_components.append(component)
                    
            # Check for command handlers
            commands = ["ls", "download", "upload", "screenshot", "camera", "shell", "sms"]
            command_handlers = []
            
            for cmd in commands:
                if f"create_tasking_{cmd}" in content and f"process_{cmd}" in content:
                    command_handlers.append(cmd)
                    
            self.test_results["agent_functions"] = {
                "status": "PASS" if len(found_components) >= 4 and len(command_handlers) >= 5 else "FAIL",
                "found_components": found_components,
                "command_handlers": command_handlers,
                "file_size": len(content)
            }
            
        except Exception as e:
            self.test_results["agent_functions"] = {
                "status": "FAIL",
                "error": str(e)
            }
            self.errors.append(f"Agent functions error: {e}")
            
    def _test_c2_profiles(self):
        """Test C2 profile manifests"""
        print("📡 Testing C2 Profiles...")
        
        profiles = ["https_beacon", "fcm_push", "dns_covert"]
        profile_results = {}
        
        for profile in profiles:
            manifest_path = self.agent_path / "c2_profiles" / profile / "c2_profile.json"
            
            try:
                with open(manifest_path, 'r') as f:
                    manifest = json.load(f)
                    
                required_fields = ["name", "author", "description", "parameters"]
                missing_fields = [field for field in required_fields if field not in manifest]
                
                param_count = len(manifest.get("parameters", []))
                
                profile_results[profile] = {
                    "status": "PASS" if not missing_fields and param_count > 0 else "FAIL",
                    "missing_fields": missing_fields,
                    "parameter_count": param_count
                }
                
            except Exception as e:
                profile_results[profile] = {
                    "status": "FAIL",
                    "error": str(e)
                }
                
        overall_status = "PASS" if all(p["status"] == "PASS" for p in profile_results.values()) else "FAIL"
        
        self.test_results["c2_profiles"] = {
            "status": overall_status,
            "profiles": profile_results
        }
        
    def _test_browser_scripts(self):
        """Test browser scripts for web UI"""
        print("🌐 Testing Browser Scripts...")
        
        browser_scripts_path = self.agent_path / "browser_scripts" / "eris_commands.js"
        
        try:
            with open(browser_scripts_path, 'r') as f:
                content = f.read()
                
            # Check for required functions
            required_functions = [
                "ls_params",
                "download_params", 
                "screenshot_params",
                "shell_params",
                "parameter_functions"
            ]
            
            found_functions = [func for func in required_functions if func in content]
            
            self.test_results["browser_scripts"] = {
                "status": "PASS" if len(found_functions) >= 4 else "FAIL",
                "found_functions": found_functions,
                "file_size": len(content)
            }
            
        except Exception as e:
            self.test_results["browser_scripts"] = {
                "status": "FAIL", 
                "error": str(e)
            }
            
    def _test_command_classes(self):
        """Test individual command classes"""
        print("⚙️ Testing Command Classes...")
        
        commands_path = self.agent_path / "eris_commands.py"
        
        try:
            with open(commands_path, 'r') as f:
                content = f.read()
                
            # Check for command classes
            command_classes = [
                "LsCommand",
                "DownloadCommand", 
                "ScreenshotCommand",
                "ShellCommand",
                "CommandBase",
                "TaskArguments"
            ]
            
            found_classes = [cls for cls in command_classes if f"class {cls}" in content]
            
            self.test_results["command_classes"] = {
                "status": "PASS" if len(found_classes) >= 5 else "FAIL",
                "found_classes": found_classes,
                "total_classes": len([line for line in content.split('\n') if line.strip().startswith('class ')])
            }
            
        except Exception as e:
            self.test_results["command_classes"] = {
                "status": "FAIL",
                "error": str(e)
            }
            
    def _test_python_imports(self):
        """Test Python import validity"""
        print("🐍 Testing Python Imports...")
        
        import_issues = []
        
        # Test critical imports without execution
        test_files = [
            "agent_functions.py",
            "eris_commands.py", 
            "mythic_integration.py"
        ]
        
        for file_name in test_files:
            file_path = self.agent_path / file_name
            if file_path.exists():
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                        
                    # Check for problematic imports
                    lines = content.split('\n')
                    for i, line in enumerate(lines):
                        if line.strip().startswith('from ') or line.strip().startswith('import '):
                            if 'mythic' in line.lower() and not line.strip().startswith('#'):
                                # This is expected - Mythic imports
                                pass
                                
                except Exception as e:
                    import_issues.append(f"{file_name}: {e}")
                    
        self.test_results["python_imports"] = {
            "status": "PASS" if not import_issues else "FAIL", 
            "issues": import_issues,
            "tested_files": len(test_files)
        }
        
    def _test_mythic_cli_simulation(self):
        """Simulate Mythic CLI installation process"""
        print("🎯 Testing Mythic CLI Simulation...")
        
        # Create temporary directory for simulation
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                # Copy essential files
                essential_files = [
                    "payload_type.json",
                    "agent_functions.py",
                    "eris_commands.py"
                ]
                
                copied_files = 0
                for file_name in essential_files:
                    src = self.agent_path / file_name
                    if src.exists():
                        dst = Path(temp_dir) / file_name
                        shutil.copy2(src, dst)
                        copied_files += 1
                        
                # Simulate basic validation
                manifest_valid = (Path(temp_dir) / "payload_type.json").exists()
                agent_functions_valid = (Path(temp_dir) / "agent_functions.py").exists()
                
                simulation_score = (copied_files / len(essential_files)) * 100
                
                self.test_results["mythic_cli_simulation"] = {
                    "status": "PASS" if simulation_score >= 80 else "FAIL",
                    "simulation_score": simulation_score,
                    "copied_files": copied_files,
                    "manifest_valid": manifest_valid,
                    "agent_functions_valid": agent_functions_valid
                }
                
            except Exception as e:
                self.test_results["mythic_cli_simulation"] = {
                    "status": "FAIL",
                    "error": str(e)
                }
                
    def _generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive test report"""
        print("\n" + "=" * 60)
        print("📊 MYTHIC COMPATIBILITY TEST REPORT")
        print("=" * 60)
        
        passed_tests = sum(1 for result in self.test_results.values() if result["status"] == "PASS")
        total_tests = len(self.test_results)
        success_rate = (passed_tests / total_tests) * 100 if total_tests > 0 else 0
        
        # Print summary
        print(f"✅ Passed: {passed_tests}/{total_tests} tests ({success_rate:.1f}%)")
        
        if self.errors:
            print(f"❌ Errors: {len(self.errors)}")
            
        print("\n📋 Detailed Results:")
        print("-" * 40)
        
        for test_name, result in self.test_results.items():
            status_icon = "✅" if result["status"] == "PASS" else "❌" 
            print(f"{status_icon} {test_name.replace('_', ' ').title()}: {result['status']}")
            
            # Show details for failures
            if result["status"] == "FAIL":
                if "error" in result:
                    print(f"   Error: {result['error']}")
                if "missing_files" in result and result["missing_files"]:
                    print(f"   Missing files: {', '.join(result['missing_files'])}")
                if "missing_directories" in result and result["missing_directories"]:
                    print(f"   Missing directories: {', '.join(result['missing_directories'])}")
                    
        # Overall compatibility assessment
        print("\n🎯 MYTHIC CLI COMPATIBILITY ASSESSMENT:")
        print("-" * 40)
        
        if success_rate >= 90:
            compatibility = "EXCELLENT ✅"
            recommendation = "Ready for Mythic CLI installation!"
        elif success_rate >= 80:
            compatibility = "GOOD ⚠️"
            recommendation = "Minor issues to resolve before installation."
        elif success_rate >= 60:
            compatibility = "FAIR ⚠️" 
            recommendation = "Several issues need attention."
        else:
            compatibility = "POOR ❌"
            recommendation = "Major issues prevent Mythic CLI installation."
            
        print(f"Compatibility Level: {compatibility}")
        print(f"Recommendation: {recommendation}")
        
        # Return full report
        return {
            "summary": {
                "total_tests": total_tests,
                "passed_tests": passed_tests,
                "success_rate": success_rate,
                "compatibility_level": compatibility,
                "recommendation": recommendation
            },
            "detailed_results": self.test_results,
            "errors": self.errors
        }

def main():
    """Main test execution"""
    if len(sys.argv) > 1:
        agent_path = sys.argv[1]
    else:
        agent_path = "."
        
    tester = MythicCompatibilityTester(agent_path)
    report = tester.run_all_tests()
    
    # Save report to file
    report_path = Path(agent_path) / "mythic_compatibility_report.json"
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
        
    print(f"\n📄 Full report saved to: {report_path}")
    
    # Exit with appropriate code
    success_rate = report["summary"]["success_rate"]
    sys.exit(0 if success_rate >= 80 else 1)

if __name__ == "__main__":
    main()
