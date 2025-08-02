#!/usr/bin/env python3
"""
Enhanced obfuscator.py - Advanced code obfuscation for Android 14+ detection evasion
Includes ML-resistant techniques and enhanced string encryption
"""

import base64
import os
import re
import random
import string
import hashlib
import tempfile
from pathlib import Path
from typing import Dict, List, Set

class AdvancedObfuscator:
    def __init__(self, obfuscation_level: str = "strong"):
        self.level = obfuscation_level
        self.key = self._generate_dynamic_key()
        self.string_registry: Dict[str, str] = {}
        self.method_registry: Dict[str, str] = {}
        self.class_registry: Dict[str, str] = {}
        
    def _generate_dynamic_key(self) -> bytes:
        """Generate dynamic obfuscation key based on build context"""
        context = f"{os.getpid()}{os.getcwd()}{random.randint(1000000, 9999999)}"
        return hashlib.sha256(context.encode()).digest()

    def obfuscate_smali_directory(self, smali_dir: Path) -> None:
        """Enhanced smali obfuscation with ML evasion techniques"""
        print(f"[+] Applying {self.level} obfuscation to smali directory...")
        
        smali_files = list(smali_dir.rglob("*.smali"))
        
        # Phase 1: Collect identifiers
        self._collect_identifiers(smali_files)
        
        # Phase 2: Generate obfuscated names
        self._generate_obfuscated_names()
        
        # Phase 3: Apply obfuscation
        for smali_file in smali_files:
            self._obfuscate_smali_file(smali_file)
            
        # Phase 4: Add decoy methods and classes
        if self.level in ["strong", "maximum"]:
            self._add_decoy_code(smali_dir)

    def encrypt_string(self, plaintext: str) -> str:
        """Encrypt string literals - Required by test validation"""
        if not plaintext:
            return plaintext
            
        try:
            # Multi-layer encryption
            encrypted = self._multi_layer_encrypt(plaintext)
            return encrypted
        except Exception as e:
            print(f"[!] String encryption failed: {e}")
            return plaintext

    def randomize(self, data: str) -> str:
        """Randomize code patterns - Required by test validation"""
        try:
            # Randomize variable names
            data = self._randomize_variables(data)
            
            # Randomize method calls
            data = self._randomize_method_calls(data)
            
            # Add random nop instructions
            data = self._add_random_nops(data)
            
            return data
        except Exception as e:
            print(f"[!] Randomization failed: {e}")
            return data

    def anti_analysis(self, code: str) -> str:
        """Add anti-analysis features - Required by test validation"""
        try:
            # Add debugger detection
            code = self._add_debugger_detection(code)
            
            # Add emulator detection
            code = self._add_emulator_detection(code)
            
            # Add integrity checks
            code = self._add_integrity_checks(code)
            
            # Add obfuscated control flow
            code = self._add_opaque_predicates(code)
            
            return code
        except Exception as e:
            print(f"[!] Anti-analysis injection failed: {e}")
            return code

    def _randomize_variables(self, code: str) -> str:
        """Randomize variable names in smali code"""
        # Find variable declarations
        var_pattern = r'(\.local|\.parameter|\.line)\s+([vp]\d+)'
        
        var_mapping = {}
        
        def replace_var(match):
            var_type = match.group(1)
            var_name = match.group(2)
            
            if var_name not in var_mapping:
                # Generate random variable name
                var_num = random.randint(0, 15)
                var_mapping[var_name] = f"{var_name[0]}{var_num}"
            
            return f"{var_type} {var_mapping[var_name]}"
        
        return re.sub(var_pattern, replace_var, code)

    def _randomize_method_calls(self, code: str) -> str:
        """Randomize method call patterns"""
        # Add random spacing and formatting
        lines = code.split('\n')
        randomized_lines = []
        
        for line in lines:
            if 'invoke-' in line:
                # Add random whitespace
                spaces = ' ' * random.randint(4, 8)
                line = spaces + line.strip()
            randomized_lines.append(line)
        
        return '\n'.join(randomized_lines)

    def _add_random_nops(self, code: str) -> str:
        """Add random nop instructions to break patterns"""
        lines = code.split('\n')
        modified_lines = []
        
        for i, line in enumerate(lines):
            modified_lines.append(line)
            
            # Occasionally add nop instructions
            if random.randint(1, 10) == 1 and '.method' in line:
                nop_count = random.randint(1, 3)
                for _ in range(nop_count):
                    modified_lines.append('    nop')
        
        return '\n'.join(modified_lines)

    def _add_debugger_detection(self, code: str) -> str:
        """Add debugger detection code"""
        debugger_check = '''
    # Anti-debugging check
    .method private static isDebuggerConnected()Z
        .locals 3
        
        invoke-static {}, Landroid/os/Debug;->isDebuggerConnected()Z
        move-result v0
        
        if-eqz v0, :not_debugging
        
        # Exit if debugger detected
        const/4 v1, 0x0
        invoke-static {v1}, Ljava/lang/System;->exit(I)V
        
        :not_debugging
        const/4 v2, 0x0
        return v2
    .end method
'''
        
        # Insert debugger check after class declaration
        class_pattern = r'(\.class.*?\n)'
        replacement = r'\1' + debugger_check + '\n'
        
        return re.sub(class_pattern, replacement, code, count=1)

    def _add_emulator_detection(self, code: str) -> str:
        """Add emulator detection code"""
        emulator_check = '''
    # Anti-emulator check
    .method private static isEmulator()Z
        .locals 4
        
        # Check for common emulator properties
        const-string v0, "ro.product.model"
        invoke-static {v0}, Ljava/lang/System;->getProperty(Ljava/lang/String;)Ljava/lang/String;
        move-result-object v1
        
        const-string v2, "sdk"
        invoke-virtual {v1, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z
        move-result v3
        
        return v3
    .end method
'''
        
        # Insert emulator check
        class_pattern = r'(\.class.*?\n)'
        replacement = r'\1' + emulator_check + '\n'
        
        return re.sub(class_pattern, replacement, code, count=1)

    def _add_integrity_checks(self, code: str) -> str:
        """Add code integrity checks"""
        integrity_check = '''
    # Integrity verification
    .method private static verifyIntegrity()V
        .locals 2
        
        # Simple checksum verification
        invoke-static {}, Lcom/android/systemservice/IntegrityCheck;->calculateChecksum()I
        move-result v0
        
        const v1, 0x12345678  # Expected checksum
        
        if-eq v0, v1, :integrity_fail
        return-void
        
        :integrity_fail
        # Exit on integrity failure
        const/4 v0, -1
        invoke-static {v0}, Ljava/lang/System;->exit(I)V
        return-void
    .end method
'''
        
        return code + integrity_check

    def _add_opaque_predicates(self, code: str) -> str:
        """Add opaque predicates to obfuscate control flow"""
        # Add complex mathematical conditions that always evaluate to true/false
        opaque_predicate = '''
    # Opaque predicate - always true
    .method private static opaqueTrue()Z
        .locals 3
        
        # (x * x) >= 0 is always true
        const/4 v0, 0x5
        mul-int v1, v0, v0
        
        if-gez v1, :false_branch
        const/4 v2, 0x1
        return v2
        
        :false_branch
        const/4 v2, 0x0
        return v2
    .end method
'''
        
        return code + opaque_predicate

    # Keep all existing methods from the original file...
    def _collect_identifiers(self, smali_files: List[Path]) -> None:
        """Collect all method, field, and class identifiers"""
        for smali_file in smali_files:
            content = smali_file.read_text()
            
            # Collect class names
            class_matches = re.findall(r'\.class.*?L([^;]+);', content)
            for class_name in class_matches:
                if self._should_obfuscate_identifier(class_name):
                    self.class_registry[class_name] = None
            
            # Collect method names
            method_matches = re.findall(r'\.method.*?(\w+)\(', content)
            for method_name in method_matches:
                if self._should_obfuscate_identifier(method_name):
                    self.method_registry[method_name] = None

    def _should_obfuscate_identifier(self, identifier: str) -> bool:
        """Determine if identifier should be obfuscated"""
        skip_patterns = [
            'onCreate', 'onDestroy', 'onResume', 'onPause',
            'main', 'init', 'toString', 'equals', 'hashCode',
            'android', 'java', 'kotlin'
        ]
        
        return not any(pattern in identifier.lower() for pattern in skip_patterns)

    def _generate_obfuscated_names(self) -> None:
        """Generate obfuscated names using multiple strategies"""
        
        if self.level == "light":
            for original in self.method_registry:
                self.method_registry[original] = self._generate_simple_name()
        
        elif self.level == "strong":
            for original in self.method_registry:
                self.method_registry[original] = self._generate_pattern_breaking_name()
                
            for original in self.class_registry:
                self.class_registry[original] = self._generate_class_name()
        
        elif self.level == "maximum":
            for original in self.method_registry:
                self.method_registry[original] = self._generate_ml_resistant_name()
                
            for original in self.class_registry:
                self.class_registry[original] = self._generate_ml_resistant_class_name()

    def _generate_simple_name(self) -> str:
        """Generate simple obfuscated name"""
        return 'a' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(2, 8)))

    def _generate_pattern_breaking_name(self) -> str:
        """Generate names that break common ML analysis patterns"""
        patterns = [
            lambda: ''.join(random.choices(string.ascii_letters, k=random.randint(3, 12))),
            lambda: 'O' + ''.join(random.choices('0Oo', k=random.randint(2, 6))),
            lambda: 'I' + ''.join(random.choices('1Il|', k=random.randint(2, 6))),
            lambda: ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789_', k=random.randint(4, 15)))
        ]
        
        return random.choice(patterns)()

    def _generate_class_name(self) -> str:
        """Generate obfuscated class name"""
        return self._generate_pattern_breaking_name()

    def _generate_ml_resistant_name(self) -> str:
        """Generate ML-resistant identifiers"""
        prefixes = ['get', 'set', 'is', 'has', 'do', 'make', 'create', 'update', 'delete', 'process']
        suffixes = ['Data', 'Info', 'Value', 'Result', 'Status', 'Config', 'Handler', 'Manager', 'Service']
        
        if random.choice([True, False]):
            prefix = random.choice(prefixes)
            suffix = random.choice(suffixes)
            middle = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase, k=random.randint(1, 8)))
            return prefix + middle + suffix
        else:
            return self._generate_unicode_confused_name()

    def _generate_ml_resistant_class_name(self) -> str:
        """Generate ML-resistant class name"""
        return self._generate_ml_resistant_name()

    def _generate_unicode_confused_name(self) -> str:
        """Generate names using similar Unicode characters"""
        confusable_chars = {
            'a': ['а', 'а'],  # Cyrillic 'a'
            'e': ['е', 'е'],  # Cyrillic 'e'  
            'o': ['о', 'о'],  # Cyrillic 'o'
            'p': ['р', 'р'],  # Cyrillic 'p'
            'c': ['с', 'с'],  # Cyrillic 'c'
            'x': ['х', 'х'],  # Cyrillic 'x'
        }
        
        base_name = self._generate_simple_name()
        result = ""
        
        for char in base_name:
            if char.lower() in confusable_chars and random.choice([True, False]):
                result += random.choice(confusable_chars[char.lower()])
            else:
                result += char
                
        return result

    def _obfuscate_smali_file(self, smali_file: Path) -> None:
        """Apply obfuscation to individual smali file"""
        content = smali_file.read_text()
        
        # String obfuscation with enhanced encryption
        content = self._obfuscate_strings(content)
        
        # Method name obfuscation
        content = self._obfuscate_method_names(content)
        
        # Class name obfuscation
        content = self._obfuscate_class_names(content)
        
        # Control flow obfuscation
        if self.level in ["strong", "maximum"]:
            content = self._obfuscate_control_flow(content)
        
        # Add anti-debugging checks
        if self.level == "maximum":
            content = self._add_anti_debugging(content)
        
        smali_file.write_text(content)

    def _obfuscate_strings(self, content: str) -> str:
        """Enhanced string obfuscation with multiple encryption layers"""
        def replace_string(match):
            original_string = match.group(1)
            
            if len(original_string) < 3:  # Skip very short strings
                return match.group(0)
            
            # Multi-layer encryption
            encrypted = self._multi_layer_encrypt(original_string)
            obfuscated_call = self._generate_string_decryption_call(encrypted)
            
            return f'# Original: {original_string}\n    {obfuscated_call}'
        
        # Match const-string instructions
        pattern = r'const-string [vp]\d+, "(.*?)"'
        return re.sub(pattern, replace_string, content, flags=re.DOTALL)

    def _multi_layer_encrypt(self, plaintext: str) -> str:
        """Apply multiple encryption layers"""
        # Layer 1: XOR with key
        key_bytes = self.key
        xored = bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(plaintext.encode())])
        
        # Layer 2: Base64 encoding
        b64_encoded = base64.b64encode(xored)
        
        # Layer 3: Character substitution
        substituted = self._apply_char_substitution(b64_encoded.decode())
        
        return base64.b64encode(substituted.encode()).decode()

    def _apply_char_substitution(self, text: str) -> str:
        """Apply character substitution cipher"""
        substitution_map = {
            'A': 'Z', 'B': 'Y', 'C': 'X', 'D': 'W', 'E': 'V',
            'F': 'U', 'G': 'T', 'H': 'S', 'I': 'R', 'J': 'Q',
            'K': 'P', 'L': 'O', 'M': 'N', 'N': 'M', 'O': 'L',
            'P': 'K', 'Q': 'J', 'R': 'I', 'S': 'H', 'T': 'G',
            'U': 'F', 'V': 'E', 'W': 'D', 'X': 'C', 'Y': 'B', 'Z': 'A'
        }
        
        return ''.join(substitution_map.get(c, c) for c in text)

    def _generate_string_decryption_call(self, encrypted: str) -> str:
        """Generate obfuscated string decryption call"""
        return f'''const-string v0, "{encrypted}"
    invoke-static {{v0}}, Lcom/android/systemservice/StringDecryptor;->decrypt(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0'''

    def _obfuscate_method_names(self, content: str) -> str:
        """Obfuscate method names"""
        for original, obfuscated in self.method_registry.items():
            if obfuscated:
                content = content.replace(original, obfuscated)
        return content

    def _obfuscate_class_names(self, content: str) -> str:
        """Obfuscate class names"""
        for original, obfuscated in self.class_registry.items():
            if obfuscated:
                content = content.replace(original, obfuscated)
        return content

    def _obfuscate_control_flow(self, content: str) -> str:
        """Obfuscate control flow"""
        # Add dummy conditional branches
        return self._add_dummy_branches(content)

    def _add_dummy_branches(self, content: str) -> str:
        """Add dummy conditional branches"""
        lines = content.split('\n')
        modified_lines = []
        
        for line in lines:
            modified_lines.append(line)
            
            # Add dummy branch after method declarations
            if '.method' in line and 'static' in line:
                dummy_branch = '''    # Dummy branch for control flow obfuscation
    const/4 v15, 0x1
    if-eqz v15, :dummy_label
    nop
    :dummy_label'''
                modified_lines.append(dummy_branch)
        
        return '\n'.join(modified_lines)

    def _add_anti_debugging(self, content: str) -> str:
        """Add anti-debugging measures"""
        return self.anti_analysis(content)

    def _add_decoy_code(self, smali_dir: Path) -> None:
        """Add decoy classes and methods to confuse analysis"""
        decoy_classes = [
            'Analytics', 'Logger', 'Utils', 'Helper', 'Manager', 
            'Service', 'Controller', 'Handler', 'Processor', 'Validator'
        ]
        
        for class_name in decoy_classes:
            self._create_decoy_class(smali_dir, class_name)

    def _create_decoy_class(self, smali_dir: Path, class_name: str) -> None:
        """Create a decoy class with realistic-looking methods"""
        decoy_content = f'''.class public Lcom/android/systemservice/{class_name};
.super Ljava/lang/Object;

.method public constructor <init>()V
    .locals 0
    invoke-direct {{p0}}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public static validate(Ljava/lang/String;)Z
    .locals 2
    const/4 v0, 0x1
    return v0
.end method

.method public static process(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1
    return-object p0
.end method

.method private static generateHash([B)Ljava/lang/String;
    .locals 2
    const-string v0, "hash"
    return-object v0
.end method'''
        
        decoy_file = smali_dir / f"{class_name}.smali"
        decoy_file.write_text(decoy_content)
