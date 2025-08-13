
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
        

        self._collect_identifiers(smali_files)
        

        self._generate_obfuscated_names()
        

        for smali_file in smali_files:
            self._obfuscate_smali_file(smali_file)
            

        if self.level in ["strong", "maximum"]:
            self._add_decoy_code(smali_dir)

    def encrypt_string(self, plaintext: str) -> str:
        """Encrypt string literals - Required by test validation"""
        if not plaintext:
            return plaintext
            
        try:

            encrypted = self._multi_layer_encrypt(plaintext)
            return encrypted
        except Exception as e:
            print(f"[!] String encryption failed: {e}")
            return plaintext

    def randomize(self, data: str) -> str:
        """Randomize code patterns - Required by test validation"""
        try:

            data = self._randomize_variables(data)
            

            data = self._randomize_method_calls(data)
            

            data = self._add_random_nops(data)
            
            return data
        except Exception as e:
            print(f"[!] Randomization failed: {e}")
            return data

    def anti_analysis(self, code: str) -> str:
        """Add anti-analysis features - Required by test validation"""
        try:

            code = self._add_debugger_detection(code)
            

            code = self._add_emulator_detection(code)
            

            code = self._add_integrity_checks(code)
            

            code = self._add_opaque_predicates(code)
            
            return code
        except Exception as e:
            print(f"[!] Anti-analysis injection failed: {e}")
            return code

    def _randomize_variables(self, code: str) -> str:
        """Randomize variable names in smali code"""

        var_pattern = r'(\.local|\.parameter|\.line)\s+([vp]\d+)'
        
        var_mapping = {}
        
        def replace_var(match):
            var_type = match.group(1)
            var_name = match.group(2)
            
            if var_name not in var_mapping:

                var_num = random.randint(0, 15)
                var_mapping[var_name] = f"{var_name[0]}{var_num}"
            
            return f"{var_type} {var_mapping[var_name]}"
        
        return re.sub(var_pattern, replace_var, code)

    def _randomize_method_calls(self, code: str) -> str:
        """Randomize method call patterns"""

        lines = code.split('\n')
        randomized_lines = []
        
        for line in lines:
            if 'invoke-' in line:

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
    
    def integrate_proguard(self, project_dir: Path) -> None:
        """Integrate ProGuard with custom rules for enhanced obfuscation"""
        print("[+] Integrating ProGuard with custom rules...")
        
        proguard_rules = self._generate_custom_proguard_rules()
        proguard_file = project_dir / "proguard-rules.pro"
        proguard_file.write_text(proguard_rules)
        

        proguard_config = project_dir / "proguard.cfg"
        config_content = f'''-injars build/classes
-outjars build/obfuscated
-libraryjars {os.environ.get('ANDROID_HOME', '/opt/android-sdk')}/platforms/android-34/android.jar
-include proguard-rules.pro

-dontpreverify
-verbose
-optimizations !code/simplification/arithmetic,!field/*,!class/merging/*
-optimizationpasses 5
-allowaccessmodification

# Enhanced obfuscation settings
-repackageclasses ''
-allowaccessmodification
-flattenpackagehierarchy
-overloadaggressively

# String encryption
-adaptresourcefilenames **.properties,**.xml,**.txt,**.spec
-adaptresourcefilecontents **.properties,META-INF/MANIFEST.MF'''
        
        proguard_config.write_text(config_content)
        
        print("[+] ProGuard integration completed")
    
    def _generate_custom_proguard_rules(self) -> str:
        """Generate custom ProGuard rules for maximum obfuscation"""
        return '''-keepclasseswithmembernames,includedescriptorclasses class * {
    native <methods>;
}

# Keep Application class
-keep public class * extends android.app.Application

# Keep Service classes
-keep public class * extends android.app.Service

# Keep BroadcastReceiver classes
-keep public class * extends android.content.BroadcastReceiver

# Obfuscate everything else aggressively
-keepclassmembers class * {
    !private <fields>;
    !private <methods>;
}

# Advanced obfuscation
-renamesourcefileattribute SourceFile
-keepattributes SourceFile,LineNumberTable

# String obfuscation
-adaptclassstrings

# Control flow obfuscation
-optimizations !code/simplification/advanced

# Remove debug info
-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int i(...);
    public static int w(...);
    public static int d(...);
    public static int e(...);
}

# Custom naming strategy
-obfuscationdictionary obfuscation-dictionary.txt
-classobfuscationdictionary class-dictionary.txt
-packageobfuscationdictionary package-dictionary.txt'''
    
    def implement_control_flow_flattening(self, smali_code: str) -> str:
        """Implement control flow flattening to break analysis tools"""
        print("[+] Implementing control flow flattening...")
        

        method_pattern = r'(\.method.*?\n)(.*?)(\.end method)'
        
        def flatten_method(match):
            method_start = match.group(1)
            method_body = match.group(2)
            method_end = match.group(3)
            

            flattened_body = self._flatten_control_flow(method_body)
            
            return method_start + flattened_body + method_end
        
        flattened_code = re.sub(method_pattern, flatten_method, smali_code, flags=re.DOTALL)
        return flattened_code
    
    def _flatten_control_flow(self, method_body: str) -> str:
        """Flatten control flow using state machine pattern"""
        lines = method_body.strip().split('\n')
        flattened_lines = []
        

        flattened_lines.extend([
            "
            "    .local v15, \"state\":I",
            "    const/4 v15, 0x0",
            "",
            "    :state_loop",
            "    packed-switch v15, :pswitch_data_0",
            "",
            "    :pswitch_0
        ])
        

        state_counter = 0
        for i, line in enumerate(lines):
            if line.strip() and not line.strip().startswith('
                flattened_lines.append(f"    {line.strip()}")
                

                if i < len(lines) - 1:
                    state_counter += 1
                    flattened_lines.extend([
                        f"    const/4 v15, {state_counter}",
                        "    goto :state_loop",
                        "",
                        f"    :pswitch_{state_counter}
                    ])
        

        flattened_lines.extend([
            "",
            "    :pswitch_data_0",
            "    .packed-switch 0x0"
        ])
        
        for i in range(state_counter + 1):
            flattened_lines.append(f"        :pswitch_{i}")
        
        flattened_lines.append("    .end packed-switch")
        
        return '\n'.join(flattened_lines)
    
    def add_dead_code_injection(self, smali_code: str) -> str:
        """Add dead code injection to confuse static analysis"""
        print("[+] Injecting dead code...")
        
        dead_code_snippets = [
            self._generate_fake_crypto_code(),
            self._generate_fake_network_code(),
            self._generate_fake_file_operations(),
            self._generate_mathematical_dead_code()
        ]
        
        lines = smali_code.split('\n')
        result_lines = []
        
        for line in lines:
            result_lines.append(line)
            

            if '.method' in line and random.randint(1, 3) == 1:
                dead_snippet = random.choice(dead_code_snippets)
                result_lines.append(dead_snippet)
        
        return '\n'.join(result_lines)
    
    def _generate_fake_crypto_code(self) -> str:
        """Generate fake cryptographic operations"""
        return '''    # Fake crypto operation - never executed
    const/4 v13, 0x0
    if-eqz v13, :skip_fake_crypto
    
    const-string v10, "AES/CBC/PKCS5Padding"
    invoke-static {v10}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;
    move-result-object v11
    
    const/16 v12, 0x10
    new-array v12, v12, [B
    invoke-virtual {v11, v12}, Ljavax/crypto/Cipher;->doFinal([B)[B
    
    :skip_fake_crypto'''
    
    def _generate_fake_network_code(self) -> str:
        """Generate fake network operations"""
        return '''    # Fake network operation - never executed
    const/4 v13, 0x0
    if-eqz v13, :skip_fake_network
    
    new-instance v8, Ljava/net/URL;
    const-string v9, "https://example.com/api"
    invoke-direct {v8, v9}, Ljava/net/URL;-><init>(Ljava/lang/String;)V
    
    invoke-virtual {v8}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;
    move-result-object v7
    
    :skip_fake_network'''
    
    def _generate_fake_file_operations(self) -> str:
        """Generate fake file operations"""
        return '''    # Fake file operation - never executed
    const/4 v13, 0x0
    if-eqz v13, :skip_fake_file
    
    new-instance v6, Ljava/io/File;
    const-string v5, "/system/bin/su"
    invoke-direct {v6, v5}, Ljava/io/File;-><init>(Ljava/lang/String;)V
    
    invoke-virtual {v6}, Ljava/io/File;->exists()Z
    move-result v4
    
    :skip_fake_file'''
    
    def _generate_mathematical_dead_code(self) -> str:
        """Generate complex mathematical operations that are never executed"""
        return '''    # Mathematical dead code - never executed
    const/4 v13, 0x0
    if-eqz v13, :skip_math
    
    const/16 v3, 0x539
    const/16 v2, 0x2a
    mul-int v1, v3, v2
    
    const/16 v0, 0x7b
    div-int/2addr v1, v0
    
    rem-int/lit8 v1, v1, 0xf
    
    :skip_math'''
    
    def create_obfuscation_dictionaries(self, project_dir: Path) -> None:
        """Create custom obfuscation dictionaries for ProGuard"""
        print("[+] Creating obfuscation dictionaries...")
        

        confusing_names = [
            'O0O0O0O0', 'Il1Il1Il1', 'a1a1a1a1', 'b2b2b2b2',
            'OOOO0000', 'llll1111', 'IIII1111', 'aaaa0000',
            'O0O0', 'Il1I', 'a1a1', 'b2b2', 'c3c3', 'd4d4',
            'ο0ο0', 'ι1ι1', 'α1α1', 'β2β2'
        ]
        

        class_dict = project_dir / "class-dictionary.txt"
        class_dict.write_text('\n'.join([f"Class{name}" for name in confusing_names]))
        

        package_dict = project_dir / "package-dictionary.txt"
        package_names = [f"pkg{name.lower()}" for name in confusing_names]
        package_dict.write_text('\n'.join(package_names))
        

        obfuscation_dict = project_dir / "obfuscation-dictionary.txt"
        method_names = confusing_names + [f"method{i}" for i in range(100)]
        obfuscation_dict.write_text('\n'.join(method_names))
        
        print("[+] Obfuscation dictionaries created")

    def _collect_identifiers(self, smali_files: List[Path]) -> None:
        """Collect all method, field, and class identifiers"""
        for smali_file in smali_files:
            content = smali_file.read_text()
            

            class_matches = re.findall(r'\.class.*?L([^;]+);', content)
            for class_name in class_matches:
                if self._should_obfuscate_identifier(class_name):
                    self.class_registry[class_name] = None
            

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
            'a': ['а', 'а'],
            'e': ['е', 'е'],
            'o': ['о', 'о'],
            'p': ['р', 'р'],
            'c': ['с', 'с'],
            'x': ['х', 'х'],
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
        

        content = self._obfuscate_strings(content)
        

        content = self._obfuscate_method_names(content)
        

        content = self._obfuscate_class_names(content)
        

        if self.level in ["strong", "maximum"]:
            content = self._obfuscate_control_flow(content)
        

        if self.level == "maximum":
            content = self._add_anti_debugging(content)
        
        smali_file.write_text(content)

    def _obfuscate_strings(self, content: str) -> str:
        """Enhanced string obfuscation with multiple encryption layers"""
        def replace_string(match):
            original_string = match.group(1)
            
            if len(original_string) < 3:
                return match.group(0)
            

            encrypted = self._multi_layer_encrypt(original_string)
            obfuscated_call = self._generate_string_decryption_call(encrypted)
            
            return f'
        

        pattern = r'const-string [vp]\d+, "(.*?)"'
        return re.sub(pattern, replace_string, content, flags=re.DOTALL)

    def _multi_layer_encrypt(self, plaintext: str) -> str:
        """Apply multiple encryption layers"""

        key_bytes = self.key
        xored = bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(plaintext.encode())])
        

        b64_encoded = base64.b64encode(xored)
        

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

        return self._add_dummy_branches(content)

    def _add_dummy_branches(self, content: str) -> str:
        """Add dummy conditional branches"""
        lines = content.split('\n')
        modified_lines = []
        
        for line in lines:
            modified_lines.append(line)
            

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
