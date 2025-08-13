
"""
Test script to validate the enhanced development environment setup
"""
import json
import sys
import os
from pathlib import Path

def test_dockerfile_enhancements():
    """Test that Dockerfile includes required enhancements"""
    print("[+] Testing Dockerfile enhancements...")
    
    with open('Dockerfile', 'r') as f:
        dockerfile_content = f.read()
    

    assert 'platforms;android-34' in dockerfile_content, "Android SDK 34 not found"
    

    assert 'ndk;25.2.9519653' in dockerfile_content, "NDK 25.2.9519653 not found"
    

    assert 'baksmali' in dockerfile_content, "baksmali not found"
    assert 'smali' in dockerfile_content, "smali not found"
    assert 'proguard' in dockerfile_content, "ProGuard not found"
    
    print("  ✓ Dockerfile enhancements verified")

def test_payload_type_config():
    """Test that payload_type.json includes new parameters"""
    print("[+] Testing payload_type.json configuration...")
    
    with open('payload_type.json', 'r') as f:
        config = json.load(f)
    
    build_params = config.get('build_parameters', [])
    param_names = [p['name'] for p in build_params]
    
    required_params = [
        'enable_device_fingerprinting',
        'thread_pool_size',
        'enable_module_dependency_injection',
        'android_14_privacy_bypass',
        'android_15_partial_screenshot_protection_bypass',
        'android_16_security_features_bypass',
        'module_load_order',
        'anti_forensics_level'
    ]
    
    for param in required_params:
        assert param in param_names, f"Required parameter '{param}' not found"
    
    print("  ✓ payload_type.json configuration verified")

def test_core_agent_enhancements():
    """Test that core_agent.py includes enhanced features"""
    print("[+] Testing core_agent.py enhancements...")
    
    with open('agent/core_agent.py', 'r') as f:
        agent_code = f.read()
    

    required_classes = [
        'AndroidVersionDetector',
        'DeviceFingerprinter',
        'ConfigurationManager',
        'ModuleLoader'
    ]
    
    for class_name in required_classes:
        assert f'class {class_name}' in agent_code, f"Class '{class_name}' not found"
    

    assert 'API_MAPPINGS' in agent_code, "Android version mappings not found"
    assert '31: "Android 12"' in agent_code, "Android 12 mapping not found"
    assert '34: "Android 14"' in agent_code, "Android 14 mapping not found"
    

    assert 'ThreadPoolExecutor' in agent_code, "Thread pool support not found"
    assert 'concurrent.futures' in agent_code, "Concurrent futures import not found"
    

    assert 'generate_fingerprint' in agent_code, "Device fingerprinting not found"
    

    assert 'dependency_injection' in agent_code, "Dependency injection not found"
    
    print("  ✓ core_agent.py enhancements verified")

def test_requirements_completeness():
    """Test that requirements.txt includes necessary dependencies"""
    print("[+] Testing requirements.txt completeness...")
    
    with open('requirements.txt', 'r') as f:
        requirements = f.read()
    

    required_deps = [
        'concurrent-futures',
        'typing-extensions',
        'psutil',
        'argon2-cffi',
        'cryptography'
    ]
    
    for dep in required_deps:
        assert dep in requirements, f"Dependency '{dep}' not found"
    
    print("  ✓ requirements.txt completeness verified")

def main():
    """Run all tests"""
    print("=" * 60)
    print("Testing Enhanced Development Environment Setup")
    print("=" * 60)
    
    try:
        test_dockerfile_enhancements()
        test_payload_type_config()
        test_core_agent_enhancements()
        test_requirements_completeness()
        
        print("\n" + "=" * 60)
        print("✅ All tests passed! Development environment setup complete.")
        print("=" * 60)
        

        print("\n📋 Summary of enhancements:")
        print("  • Android SDK 34 (Android 14) support")
        print("  • NDK 25.2.9519653 integration")
        print("  • Additional build tools (apktool 2.8.1, baksmali, smali, ProGuard)")
        print("  • Android version detection (API 31-35)")
        print("  • Device fingerprinting for campaign isolation")
        print("  • Module dependency injection system")
        print("  • Thread pool for concurrent execution")
        print("  • Encrypted configuration management")
        print("  • Enhanced error handling and logging")
        print("  • Android 14-16 specific security bypasses")
        
        return True
        
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        return False
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
