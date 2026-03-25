#!/usr/bin/env python3
"""
Enhanced SO Library & C File Analysis Bot with Parallel Processing
Features:
- Parallel .so file processing
- PATCH_LIB and HOOK_LIB code generation
- C file hook generation with AI (DeepSeek + OpenRouter fallback)
- Configurable output limits
- Unique function implementations
- Improved error handling and UI
"""

import os
import json
import subprocess
import logging
import re
import asyncio
import aiohttp
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor
import hashlib

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ContextTypes,
    filters
)
from openai import OpenAI

# Configure logging with better formatting
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Configuration
OWNER_ID = user-id-here
TELEGRAM_BOT_TOKEN = "bot-token"

# AI API Configuration - Multiple fallback options
DEEPSEEK_API_KEY = "sk-ef16c698d1af41aa8ac0f55e3cfa342d"
DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"
DEEPSEEK_MODEL = "deepseek-chat"

OPENROUTER_API_KEY = "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"
OPENROUTER_API_URL = "https://openrouter.ai/api/v1"

# Models (aligned with req.py)
MODEL_TEXT = "mistralai/devstral-2512:free"
MODEL_VISION = "qwen/qwen-2.5-vl-7b-instruct:free"
MODEL_GEN = "mistralai/devstral-2512:free"

# Multiple OpenRouter models to try (in order of preference)
OPENROUTER_MODELS = [
    MODEL_TEXT,
    MODEL_GEN,
    MODEL_VISION,
]

# Initialize OpenAI client for OpenRouter (better compatibility with free models)
openrouter_client = OpenAI(
    base_url=OPENROUTER_API_URL,
    api_key=OPENROUTER_API_KEY
)

# Get script directory for saving files
SCRIPT_DIR = Path(__file__).parent.resolve()
USERS_FILE = SCRIPT_DIR / "users.json"
CONFIG_FILE = SCRIPT_DIR / "config.json"
ANALYSIS_DIR = SCRIPT_DIR / "analysis_results"
ANALYSIS_DIR.mkdir(exist_ok=True)

# Default limits
DEFAULT_PATCH_LIMIT = 15
DEFAULT_HOOK_LIMIT = 10


class ConfigManager:
    """Manages configuration for patch and hook limits"""
    
    def __init__(self):
        self.config = self._load_config()
    
    def _load_config(self):
        """Load config from JSON file"""
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, 'r') as f:
                    return json.load(f)
            except:
                return {
                    "patch_limit": DEFAULT_PATCH_LIMIT,
                    "hook_limit": DEFAULT_HOOK_LIMIT
                }
        return {
            "patch_limit": DEFAULT_PATCH_LIMIT,
            "hook_limit": DEFAULT_HOOK_LIMIT
        }
    
    def _save_config(self):
        """Save config to JSON file"""
        with open(CONFIG_FILE, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    def set_patch_limit(self, limit: int):
        """Set patch output limit"""
        self.config["patch_limit"] = limit
        self._save_config()
    
    def set_hook_limit(self, limit: int):
        """Set hook output limit"""
        self.config["hook_limit"] = limit
        self._save_config()
    
    def get_patch_limit(self) -> int:
        return self.config.get("patch_limit", DEFAULT_PATCH_LIMIT)
    
    def get_hook_limit(self) -> int:
        return self.config.get("hook_limit", DEFAULT_HOOK_LIMIT)


config_manager = ConfigManager()


class UserManager:
    """Manages user permissions and admin list"""
    
    def __init__(self):
        self.data = self._load_data()
    
    def _load_data(self):
        """Load user data from JSON file"""
        if USERS_FILE.exists():
            try:
                with open(USERS_FILE, 'r') as f:
                    return json.load(f)
            except:
                return {
                    "admins": [],
                    "approved_users": [],
                    "disapproved_users": []
                }
        return {
            "admins": [],
            "approved_users": [],
            "disapproved_users": []
        }
    
    def _save_data(self):
        """Save user data to JSON file"""
        with open(USERS_FILE, 'w') as f:
            json.dump(self.data, f, indent=2)
    
    def is_owner(self, user_id: int) -> bool:
        return user_id == OWNER_ID
    
    def is_admin(self, user_id: int) -> bool:
        return user_id in self.data["admins"]
    
    def is_approved(self, user_id: int) -> bool:
        return user_id in self.data["approved_users"]
    
    def approve_user(self, user_id: int):
        if user_id not in self.data["approved_users"]:
            self.data["approved_users"].append(user_id)
            if user_id in self.data["disapproved_users"]:
                self.data["disapproved_users"].remove(user_id)
            self._save_data()
    
    def disapprove_user(self, user_id: int):
        if user_id in self.data["approved_users"]:
            self.data["approved_users"].remove(user_id)
        if user_id not in self.data["disapproved_users"]:
            self.data["disapproved_users"].append(user_id)
        self._save_data()
    
    def add_admin(self, user_id: int):
        if user_id not in self.data["admins"]:
            self.data["admins"].append(user_id)
            self._save_data()
    
    def remove_admin(self, user_id: int):
        if user_id in self.data["admins"]:
            self.data["admins"].remove(user_id)
            self._save_data()


user_manager = UserManager()


class Radare2Analyzer:
    """Enhanced analyzer using radare2 for comprehensive binary analysis"""
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.lib_name = Path(file_path).name
        self.analysis_data = {}
    
    def run_r2_command(self, command: str) -> str:
        """Execute radare2 command and return output"""
        try:
            result = subprocess.run(
                ['r2', '-q', '-c', command, self.file_path],
                capture_output=True,
                text=True,
                timeout=60
            )
            return result.stdout
        except Exception as e:
            logger.error(f"r2 command '{command}' failed: {e}")
            return f"Error: {e}"
    
    async def analyze_async(self) -> Dict:
        """Perform comprehensive radare2 analysis with parallel execution"""
        logger.info(f"Starting parallel radare2 analysis of {self.lib_name}")
        
        # Commands to run in parallel
        commands = {
            "exports": "iE",
            "imports": "ii",
            "strings": "izz",
            "symbols": "is",
            "sections": "iS",
            "relocations": "ir",
            "info": "i",
            "entrypoints": "ie",
            "libraries": "il",
            "binary_info": "ij"
        }
        
        # Run commands in parallel using ThreadPoolExecutor
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=len(commands)) as executor:
            tasks = {
                key: loop.run_in_executor(executor, self.run_r2_command, cmd)
                for key, cmd in commands.items()
            }
            
            # Wait for all tasks to complete
            for key, task in tasks.items():
                self.analysis_data[key] = await task
        
        logger.info(f"Parallel radare2 analysis complete for {self.lib_name}")
        return self.analysis_data
    
    def save_analysis(self) -> tuple:
        """Save analysis to JSON and TXT files"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"{self.lib_name}_{timestamp}"
        
        # Save JSON
        json_path = ANALYSIS_DIR / f"{base_name}.json"
        with open(json_path, 'w') as f:
            json.dump(self.analysis_data, f, indent=2)
        
        # Save TXT
        txt_path = ANALYSIS_DIR / f"{base_name}.txt"
        with open(txt_path, 'w') as f:
            f.write(f"Radare2 Library Analysis Report\n")
            f.write(f"{'='*80}\n")
            f.write(f"Library: {self.lib_name}\n")
            f.write(f"Analysis Date: {datetime.now().isoformat()}\n")
            f.write(f"{'='*80}\n\n")
            
            for key, value in self.analysis_data.items():
                f.write(f"\n{'='*80}\n")
                f.write(f"{key.upper().replace('_', ' ')}\n")
                f.write(f"{'='*80}\n")
                f.write(f"{value}\n")
        
        return str(json_path), str(txt_path)


class CFileAnalyzer:
    """Analyzer for C decompiled files"""
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.file_name = Path(file_path).name
        self.content = ""
    
    async def load_content(self):
        """Load C file content"""
        with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
            self.content = f.read()
        return self.content
    
    def extract_functions(self) -> List[Dict]:
        """Extract function signatures and addresses from C file"""
        functions = []
        
        # Pattern to match function definitions with addresses
        # Example: __int64 __fastcall sub_6646538(_QWORD *a1)
        pattern = r'(__int64|int|void|char|float|double)\s+(?:__fastcall\s+)?(\w+)\s*\([^)]*\)'
        
        matches = re.finditer(pattern, self.content)
        for match in matches:
            func_name = match.group(2)
            if func_name.startswith('sub_'):
                # Extract hex address from function name
                addr = func_name.replace('sub_', '')
                if addr:
                    functions.append({
                        'name': func_name,
                        'address': f"0x{addr}",
                        'signature': match.group(0)
                    })
        
        return functions


class AIAnalyzer:
    """AI-powered analysis with DeepSeek (primary) and OpenRouter (fallback)"""
    
    @staticmethod
    def _load_previous_values(lib_name: str) -> Dict:
        """Load previously extracted values for this library"""
        history_file = ANALYSIS_DIR / f"{lib_name}_value_history.json"
        if history_file.exists():
            try:
                with open(history_file, 'r') as f:
                    data = json.load(f)
                    return {
                        'patches': set(data.get('previous_patches', [])),
                        'hooks': set(data.get('previous_hooks', [])),
                        'functions': set(data.get('previous_functions', []))
                    }
            except:
                return {'patches': set(), 'hooks': set(), 'functions': set()}
        return {'patches': set(), 'hooks': set(), 'functions': set()}
    
    @staticmethod
    def _save_values(lib_name: str, patches: list, hooks: list, functions: list):
        """Save extracted values to history"""
        history_file = ANALYSIS_DIR / f"{lib_name}_value_history.json"
        previous = AIAnalyzer._load_previous_values(lib_name)
        
        previous['patches'].update(patches)
        previous['hooks'].update(hooks)
        previous['functions'].update(functions)
        
        with open(history_file, 'w') as f:
            json.dump({
                'previous_patches': list(previous['patches']),
                'previous_hooks': list(previous['hooks']),
                'previous_functions': list(previous['functions']),
                'last_updated': datetime.now().isoformat()
            }, f, indent=2)
    
    @staticmethod
    async def _call_ai_api(system_prompt: str, user_prompt: str, temperature: float = 0.9, timeout: int = 120) -> Dict:
        """
        Call AI API with automatic fallback from DeepSeek to OpenRouter (tries multiple models)
        Returns: {'success': bool, 'content': str, 'provider': str, 'error': str}
        """
        
        # Try DeepSeek first (if it has balance)
        try:
            logger.info("🔵 Attempting DeepSeek API...")
            async with aiohttp.ClientSession() as session:
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {DEEPSEEK_API_KEY}"
                }
                
                payload = {
                    "model": DEEPSEEK_MODEL,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    "temperature": temperature
                }
                
                async with session.post(DEEPSEEK_API_URL, headers=headers, json=payload, timeout=timeout) as response:
                    if response.status == 200:
                        result = await response.json()
                        content = result['choices'][0]['message']['content']
                        logger.info("✅ DeepSeek API successful")
                        return {
                            'success': True,
                            'content': content,
                            'provider': 'DeepSeek',
                            'error': None
                        }
                    elif response.status == 402:
                        error_text = await response.text()
                        logger.warning(f"⚠️ DeepSeek: No balance, skipping to fallback")
                    else:
                        error_text = await response.text()
                        logger.warning(f"⚠️ DeepSeek API failed: {response.status}")
        
        except Exception as e:
            logger.warning(f"⚠️ DeepSeek API exception: {str(e)}")
        
        # Fallback to OpenRouter - try multiple models
        logger.info("🟢 Trying OpenRouter API with multiple models...")
        
        for idx, model in enumerate(OPENROUTER_MODELS, 1):
            try:
                logger.info(f"   📡 Attempt {idx}/{len(OPENROUTER_MODELS)}: {model}")
                
                # Run synchronous OpenAI call in thread pool to avoid blocking
                loop = asyncio.get_event_loop()
                
                def call_openrouter():
                    response = openrouter_client.chat.completions.create(
                        model=model,
                        messages=[
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt}
                        ],
                        temperature=temperature
                    )
                    return response.choices[0].message.content
                
                # Execute in thread pool with timeout
                content = await asyncio.wait_for(
                    loop.run_in_executor(None, call_openrouter),
                    timeout=timeout
                )
                
                logger.info(f"✅ OpenRouter successful with model: {model}")
                return {
                    'success': True,
                    'content': content,
                    'provider': f'OpenRouter ({model.split("/")[-1].replace(":free", "")})',
                    'error': None
                }
            
            except asyncio.TimeoutError:
                logger.warning(f"   ⏱️ Timeout with {model}, trying next...")
                continue
            except Exception as e:
                error_msg = str(e)
                if "404" in error_msg and "data policy" in error_msg.lower():
                    logger.warning(f"   ⚠️ {model} requires privacy config, trying next...")
                elif "rate limit" in error_msg.lower():
                    logger.warning(f"   ⚠️ {model} rate limited, trying next...")
                else:
                    logger.warning(f"   ❌ {model} failed: {error_msg[:100]}")
                continue
        
        # All APIs failed
        logger.error("❌ All AI APIs exhausted")
        return {
            'success': False,
            'content': None,
            'provider': None,
            'error': (
                "All AI APIs failed:\n"
                "• DeepSeek: Insufficient balance\n"
                "• OpenRouter: All models failed or require configuration\n\n"
                "💡 Solutions:\n"
                "1. Add balance to DeepSeek account\n"
                "2. Configure privacy settings at: https://openrouter.ai/settings/privacy\n"
                "3. Try again later (rate limits may be temporary)"
            )
        }
    
    @staticmethod
    async def analyze_with_ai_parallel(lib_name: str, analysis_data: Dict) -> Dict:
        """Send multiple parallel requests to AI for faster analysis"""
        
        # Load previously extracted values
        previous_values = AIAnalyzer._load_previous_values(lib_name)
        
        patch_limit = config_manager.get_patch_limit()
        hook_limit = config_manager.get_hook_limit()
        
        # Split analysis data into chunks for parallel processing
        exports = analysis_data.get('exports', '')
        imports = analysis_data.get('imports', '')
        strings = analysis_data.get('strings', '')
        symbols = analysis_data.get('symbols', '')
        sections = analysis_data.get('sections', '')
        
        # Create multiple AI requests in parallel
        tasks = [
            AIAnalyzer._request_patches(lib_name, exports, symbols, sections, previous_values['patches'], patch_limit),
            AIAnalyzer._request_hooks(lib_name, exports, imports, strings, previous_values['hooks'], previous_values['functions'], hook_limit)
        ]
        
        # Execute all requests in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Combine results
        patches_result = results[0] if not isinstance(results[0], Exception) else {'patches': [], 'error': str(results[0]), 'provider': None}
        hooks_result = results[1] if not isinstance(results[1], Exception) else {'hooks': [], 'error': str(results[1]), 'provider': None}
        
        # Save new values
        all_patches = [p['address'] for p in patches_result.get('patches', [])]
        all_hooks = [h['address'] for h in hooks_result.get('hooks', [])]
        all_functions = [h['function_name'] for h in hooks_result.get('hooks', [])]
        
        if all_patches or all_hooks:
            AIAnalyzer._save_values(lib_name, all_patches, all_hooks, all_functions)
        
        return {
            'success': True,
            'lib_name': lib_name,
            'patches': patches_result.get('patches', []),
            'hooks': hooks_result.get('hooks', []),
            'provider_patches': patches_result.get('provider', 'Unknown'),
            'provider_hooks': hooks_result.get('provider', 'Unknown'),
            'previous_count': {
                'patches': len(previous_values['patches']),
                'hooks': len(previous_values['hooks'])
            },
            'timestamp': datetime.now().isoformat()
        }
    
    @staticmethod
    async def _request_patches(lib_name: str, exports: str, symbols: str, sections: str, previous: set, limit: int) -> Dict:
        """Request PATCH_LIB format from AI"""
        
        exclusion_text = ""
        if previous:
            exclusion_text = f"\n\n**CRITICAL: DO NOT USE THESE PREVIOUSLY EXTRACTED ADDRESSES:**\n{', '.join(sorted(previous))}\n\nYou MUST find NEW addresses!"
        
        system_prompt = f"""You are an expert reverse engineer specializing in Android game anti-cheat bypass.

Your task is to analyze the binary data and generate EXACTLY {limit} PATCH_LIB entries.
Identify which functions likely ban, kick, or suspend players, and prioritize those targets.

**FORMAT REQUIRED:**
PATCH_LIB("{lib_name}", "0xADDRESS", "00 00 80 D2 C0 03 5F D6");

**Requirements:**
1. Extract {limit} unique memory addresses from the provided data
2. Each address must be a real address from exports, symbols, or sections
3. Use the hex patch bytes: "00 00 80 D2 C0 03 5F D6" (ARM64 NOP + RET)
4. Focus on security check functions, validation routines, anti-cheat checks
5. DO NOT repeat previously used addresses
6. Addresses should target functions that can be bypassed

**Response Format:**
Provide ONLY the PATCH_LIB lines, one per line, no explanations."""

        user_prompt = f"""Library: {lib_name}

EXPORTS:
{exports}

SYMBOLS:
{symbols}

SECTIONS:
{sections}
{exclusion_text}

Generate {limit} PATCH_LIB entries for bypassing anti-cheat mechanisms. Focus on functions that cause player bans or kicks."""

        # Call AI with automatic fallback
        ai_response = await AIAnalyzer._call_ai_api(system_prompt, user_prompt, temperature=0.9, timeout=120)
        
        if not ai_response['success']:
            return {'patches': [], 'error': ai_response['error'], 'provider': None}
        
        # Parse PATCH_LIB entries
        patches = []
        pattern = r'PATCH_LIB\s*\(\s*"([^"]+)"\s*,\s*"(0x[0-9a-fA-F]+)"\s*,\s*"([^"]+)"\s*\)'
        matches = re.finditer(pattern, ai_response['content'])
        
        for match in matches:
            lib, addr, bytes_str = match.groups()
            addr_lower = addr.lower()
            if addr_lower not in {p.lower() for p in previous}:
                patches.append({
                    'lib': lib,
                    'address': addr,
                    'bytes': bytes_str,
                    'code': f'PATCH_LIB("{lib}", "{addr}", "{bytes_str}");'
                })
        
        return {
            'patches': patches[:limit],
            'provider': ai_response['provider']
        }
    
    @staticmethod
    async def _request_hooks(lib_name: str, exports: str, imports: str, strings: str, previous_hooks: set, previous_functions: set, limit: int) -> Dict:
        """Request HOOK_LIB format from AI with unique function implementations"""
        
        exclusion_text = ""
        if previous_hooks:
            exclusion_text = f"\n\n**CRITICAL: DO NOT USE THESE PREVIOUSLY EXTRACTED ADDRESSES:**\n{', '.join(sorted(previous_hooks))}"
        
        if previous_functions:
            exclusion_text += f"\n\n**DO NOT USE THESE FUNCTION PATTERNS:**\n{', '.join(sorted(previous_functions))}\n\nCreate COMPLETELY DIFFERENT function implementations!"
        
        system_prompt = f"""You are an expert reverse engineer creating hook functions for Android game modding.

Your task is to generate EXACTLY {limit} unique HOOK implementations.
Identify which functions likely ban, kick, or suspend players, and prioritize those targets.

**FORMAT REQUIRED (Generate BOTH formats for each hook):**

Format 1 - NO_ORIG (Direct bypass):
```
HOOK_LIB_NO_ORIG("{lib_name}", "0xADDRESS", function_name);
```

Format 2 - WITH_ORIG (Wrapper with modifications):
```
__int64 (*orig_function_name)(__int64, __int64*);
__int64 function_name(__int64 a1, __int64 *a2) {{
    // Unique implementation here
    return orig_function_name(a1, a2);
}}
HOOK_LIB("{lib_name}", "0xADDRESS", function_name, orig_function_name);
```

**CRITICAL REQUIREMENTS:**
1. Generate {limit} DIFFERENT hook implementations
2. Each function must have UNIQUE logic - DO NOT repeat patterns
3. Use different variable names, different checks, different modifications
4. Create diverse bypass strategies:
   - Memory zeroing (different offsets each time)
   - Return value manipulation (different values)
   - Parameter validation bypass (different conditions)
   - Flag manipulation (different flags)
   - Pointer nullification (different pointers)
5. Extract real addresses from the binary data
6. Use creative function names (not just sub_XXXXX)
7. Add meaningful comments explaining what each hook does

**Response Format:**
For each hook, provide:
1. Function implementation with unique logic
2. Both HOOK_LIB_NO_ORIG and HOOK_LIB formats
3. Comment explaining bypass strategy"""

        user_prompt = f"""Library: {lib_name}

EXPORTS (Functions to hook):
{exports}

IMPORTS (External dependencies):
{imports}

STRINGS (Context clues):
{strings}
{exclusion_text}

Generate {limit} UNIQUE hook implementations with DIVERSE bypass strategies. Focus on functions that ban players. Make each function implementation COMPLETELY DIFFERENT from others!"""

        # Call AI with automatic fallback
        ai_response = await AIAnalyzer._call_ai_api(system_prompt, user_prompt, temperature=1.0, timeout=180)
        
        if not ai_response['success']:
            return {'hooks': [], 'error': ai_response['error'], 'provider': None}
        
        # Parse hook implementations
        hooks = []
        
        # Pattern for HOOK_LIB_NO_ORIG
        pattern_no_orig = r'HOOK_LIB_NO_ORIG\s*\(\s*"([^"]+)"\s*,\s*"(0x[0-9a-fA-F]+)"\s*,\s*(\w+)\s*\)'
        
        # Pattern for HOOK_LIB with implementation
        pattern_impl = r'(__int64[^;]+;[\s\S]+?HOOK_LIB\s*\([^)]+\)\s*;)'
        
        # Extract implementations
        impl_matches = re.finditer(pattern_impl, ai_response['content'])
        for match in impl_matches:
            impl_block = match.group(1)
            
            # Extract address from this block
            addr_match = re.search(r'"(0x[0-9a-fA-F]+)"', impl_block)
            if addr_match:
                addr = addr_match.group(1)
                addr_lower = addr.lower()
                
                if addr_lower not in {h.lower() for h in previous_hooks}:
                    # Extract function name
                    func_match = re.search(r'(\w+)\s*\(__int64', impl_block)
                    func_name = func_match.group(1) if func_match else f"hook_{addr[2:]}"
                    
                    if func_name not in previous_functions:
                        hooks.append({
                            'lib': lib_name,
                            'address': addr,
                            'function_name': func_name,
                            'code': impl_block.strip(),
                            'type': 'HOOK_LIB'
                        })
        
        # Also extract NO_ORIG hooks
        no_orig_matches = re.finditer(pattern_no_orig, ai_response['content'])
        for match in no_orig_matches:
            lib, addr, func_name = match.groups()
            addr_lower = addr.lower()
            
            if addr_lower not in {h.lower() for h in previous_hooks}:
                if func_name not in previous_functions:
                    hooks.append({
                        'lib': lib,
                        'address': addr,
                        'function_name': func_name,
                        'code': f'HOOK_LIB_NO_ORIG("{lib}", "{addr}", {func_name});',
                        'type': 'HOOK_LIB_NO_ORIG'
                    })
        
        return {
            'hooks': hooks[:limit],
            'provider': ai_response['provider']
        }
    
    @staticmethod
    async def analyze_c_file(file_name: str, content: str) -> Dict:
        """Analyze C file and generate hooks"""
        
        previous_values = AIAnalyzer._load_previous_values(file_name)
        hook_limit = config_manager.get_hook_limit()
        
        # Extract real library name from file
        lib_name_match = re.search(r'(lib\w+\.so)', file_name)
        real_lib_name = lib_name_match.group(1) if lib_name_match else "libanogs.so"
        
        exclusion_text = ""
        if previous_values['hooks']:
            exclusion_text = f"\n\n**CRITICAL: DO NOT USE THESE ADDRESSES:**\n{', '.join(sorted(previous_values['hooks']))}"
        
        if previous_values['functions']:
            exclusion_text += f"\n\n**DO NOT REUSE THESE FUNCTION PATTERNS:**\n{', '.join(sorted(previous_values['functions']))}"
        
        primary_chunk = content
        
        system_prompt = f"""You are an expert C code analyzer and hook generator for game modding.

Analyze the provided decompiled C code and generate {hook_limit} UNIQUE hook implementations.

**REQUIREMENTS:**
1. Identify {hook_limit} different functions from the C code
2. Extract the real function address from function names (e.g., sub_51B774 → 0x51B774)
3. Generate BOTH hook formats for each function
4. Create UNIQUE implementations - each should use DIFFERENT bypass techniques
5. Use the real library name: {real_lib_name}

**HOOK FORMATS TO GENERATE:**

Format 1 - Simple Hook:
```
HOOK_LIB_NO_ORIG("{real_lib_name}", "0xADDRESS", function_name);
```

Format 2 - Advanced Hook with unique implementation:
```
__int64 (*orig_function)(__int64, __int64*);
__int64 function(__int64 a1, __int64 *a2) {{
    // UNIQUE bypass logic here - make it DIFFERENT from others!
    return orig_function(a1, a2);
}}
HOOK_LIB("{real_lib_name}", "0xADDRESS", function, orig_function); // description
```

**DIVERSITY REQUIREMENTS:**
Each hook MUST use different techniques - different memory offsets, return values, validations, etc.

**OUTPUT:**
Generate {hook_limit} hooks with COMPLETELY DIFFERENT implementations. Add descriptive comments for each."""

        user_prompt = f"""C Decompiled Code ({len(content)} bytes):

{primary_chunk}
{exclusion_text}

Analyze the code and generate {hook_limit} UNIQUE hook implementations with DIVERSE bypass strategies for {real_lib_name}. Focus on ban-related functions."""

        # Call AI with automatic fallback
        ai_response = await AIAnalyzer._call_ai_api(system_prompt, user_prompt, temperature=1.0, timeout=300)
        
        if not ai_response['success']:
            return {
                'success': False,
                'error': ai_response['error'],
                'provider': None
            }
        
        # Parse all hooks
        hooks = []
        
        # Extract full hook implementations
        pattern_impl = r'(__int64[^;]+;[\s\S]+?HOOK_LIB\s*\([^)]+\)\s*;[^\n]*)'
        impl_matches = re.finditer(pattern_impl, ai_response['content'])
        
        for match in impl_matches:
            impl_block = match.group(1)
            
            # Extract address
            addr_match = re.search(r'"(0x[0-9a-fA-F]+)"', impl_block)
            if addr_match:
                addr = addr_match.group(1)
                addr_lower = addr.lower()
                
                if addr_lower not in {h.lower() for h in previous_values['hooks']}:
                    # Extract function name
                    func_match = re.search(r'(\w+)\s*\(__int64', impl_block)
                    func_name = func_match.group(1) if func_match else f"hook_{addr[2:]}"
                    
                    if func_name not in previous_values['functions']:
                        hooks.append({
                            'lib': real_lib_name,
                            'address': addr,
                            'function_name': func_name,
                            'code': impl_block.strip(),
                            'type': 'HOOK_LIB'
                        })
        
        # Extract NO_ORIG hooks
        pattern_no_orig = r'HOOK_LIB_NO_ORIG\s*\(\s*"([^"]+)"\s*,\s*"(0x[0-9a-fA-F]+)"\s*,\s*(\w+)\s*\)'
        no_orig_matches = re.finditer(pattern_no_orig, ai_response['content'])
        
        for match in no_orig_matches:
            lib, addr, func_name = match.groups()
            addr_lower = addr.lower()
            
            if addr_lower not in {h.lower() for h in previous_values['hooks']}:
                if func_name not in previous_values['functions']:
                    hooks.append({
                        'lib': lib,
                        'address': addr,
                        'function_name': func_name,
                        'code': f'HOOK_LIB_NO_ORIG("{lib}", "{addr}", {func_name});',
                        'type': 'HOOK_LIB_NO_ORIG'
                    })
        
        # Save new hooks
        all_addrs = [h['address'] for h in hooks]
        all_funcs = [h['function_name'] for h in hooks]
        if hooks:
            AIAnalyzer._save_values(file_name, [], all_addrs, all_funcs)
        
        return {
            'success': True,
            'lib_name': real_lib_name,
            'hooks': hooks[:hook_limit],
            'provider': ai_response['provider'],
            'previous_count': len(previous_values['hooks']),
            'timestamp': datetime.now().isoformat()
        }


# Bot Handlers

def create_main_keyboard(user_id: int):
    """Create main menu keyboard based on user permissions"""
    keyboard = []
    
    if user_manager.is_owner(user_id) or user_manager.is_admin(user_id):
        keyboard.append([
            InlineKeyboardButton("👤 Approve User", callback_data="menu_approve"),
            InlineKeyboardButton("🚫 Disapprove User", callback_data="menu_disapprove")
        ])
    
    if user_manager.is_owner(user_id):
        keyboard.append([
            InlineKeyboardButton("⚡ Add Admin", callback_data="menu_add_admin"),
            InlineKeyboardButton("❌ Remove Admin", callback_data="menu_remove_admin")
        ])
        keyboard.append([
            InlineKeyboardButton("⚙️ Set Patch Limit", callback_data="menu_set_patch"),
            InlineKeyboardButton("⚙️ Set Hook Limit", callback_data="menu_set_hook")
        ])
    
    if user_manager.is_approved(user_id):
        keyboard.append([
            InlineKeyboardButton("📤 Analyze .so Library", callback_data="menu_analyze_so"),
            InlineKeyboardButton("📄 Analyze .c File", callback_data="menu_analyze_c")
        ])
    
    keyboard.append([
        InlineKeyboardButton("ℹ️ My Status", callback_data="menu_status"),
        InlineKeyboardButton("❓ Help", callback_data="menu_help")
    ])
    
    return InlineKeyboardMarkup(keyboard)


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle start command with button UI"""
    user_id = update.effective_user.id
    username = update.effective_user.username or "User"
    
    welcome_text = (
        "🤖 <b>Advanced SO &amp; C File Analyzer v2.0</b>\n\n"
        f"Welcome <b>{username}</b>!\n\n"
        "✨ <b>Features:</b>\n"
        "• Parallel .so analysis\n"
        "• PATCH_LIB code generation\n"
        "• HOOK_LIB code generation\n"
        "• C file hook analysis\n"
        "• Configurable output limits\n"
        "• <b>Dual AI engines with auto-fallback</b>\n\n"
        f"🆔 Your User ID: <code>{user_id}</code>\n\n"
        "Choose an option below:"
    )
    
    keyboard = create_main_keyboard(user_id)
    
    await update.message.reply_text(
        welcome_text,
        reply_markup=keyboard,
        parse_mode='HTML'
    )


async def set_patch_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /set_patch command"""
    user_id = update.effective_user.id
    
    if not user_manager.is_owner(user_id):
        await update.message.reply_text("❌ Owner only command")
        return
    
    try:
        if len(context.args) < 1:
            current = config_manager.get_patch_limit()
            await update.message.reply_text(
                f"⚙️ <b>Current patch limit:</b> {current}\n\n"
                f"<b>Usage:</b> <code>/set_patch &lt;number&gt;</code>\n"
                f"<b>Example:</b> <code>/set_patch 20</code>",
                parse_mode='HTML'
            )
            return
        
        limit = int(context.args[0])
        if limit < 1 or limit > 50:
            await update.message.reply_text("❌ Limit must be between 1 and 50")
            return
        
        config_manager.set_patch_limit(limit)
        await update.message.reply_text(f"✅ Patch limit set to <b>{limit}</b>", parse_mode='HTML')
    
    except ValueError:
        await update.message.reply_text("❌ Invalid number")


async def set_hook_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /set_hook command"""
    user_id = update.effective_user.id
    
    if not user_manager.is_owner(user_id):
        await update.message.reply_text("❌ Owner only command")
        return
    
    try:
        if len(context.args) < 1:
            current = config_manager.get_hook_limit()
            await update.message.reply_text(
                f"⚙️ <b>Current hook limit:</b> {current}\n\n"
                f"<b>Usage:</b> <code>/set_hook &lt;number&gt;</code>\n"
                f"<b>Example:</b> <code>/set_hook 15</code>",
                parse_mode='HTML'
            )
            return
        
        limit = int(context.args[0])
        if limit < 1 or limit > 30:
            await update.message.reply_text("❌ Limit must be between 1 and 30")
            return
        
        config_manager.set_hook_limit(limit)
        await update.message.reply_text(f"✅ Hook limit set to <b>{limit}</b>", parse_mode='HTML')
    
    except ValueError:
        await update.message.reply_text("❌ Invalid number")


async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle button callbacks"""
    query = update.callback_query
    user_id = query.from_user.id
    data = query.data
    
    await query.answer()
    
    if data == "menu_status":
        status_text = f"👤 <b>Your Status</b>\n\n🆔 User ID: <code>{user_id}</code>\n\n"
        
        if user_manager.is_owner(user_id):
            status_text += "🔑 Role: <b>OWNER</b>\n✅ All permissions granted\n\n"
        elif user_manager.is_admin(user_id):
            status_text += "⚡ Role: <b>ADMIN</b>\n✅ Can manage users\n\n"
        elif user_manager.is_approved(user_id):
            status_text += "✅ Status: <b>APPROVED</b>\n✅ Can analyze files\n\n"
        else:
            status_text += "❌ Status: <b>NOT APPROVED</b>\n❌ Limited access\n\n💡 Contact admin for approval\n\n"
        
        status_text += f"⚙️ <b>Current Settings:</b>\n"
        status_text += f"• Patch limit: {config_manager.get_patch_limit()}\n"
        status_text += f"• Hook limit: {config_manager.get_hook_limit()}\n\n"
        status_text += f"🤖 <b>AI Engines:</b>\n"
        status_text += f"• Primary: DeepSeek\n"
        status_text += f"• Fallback: OpenRouter (Kimi-K2)"
        
        await query.edit_message_text(
            status_text,
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("« Back to Menu", callback_data="menu_main")
            ]]),
            parse_mode='HTML'
        )
    
    elif data == "menu_help":
        help_text = (
            "📚 <b>Bot Commands &amp; Features</b>\n\n"
            "🔘 <b>Button Interface:</b>\n"
            "• <i>Analyze .so Library</i> - Upload .so for PATCH_LIB and HOOK_LIB code\n"
            "• <i>Analyze .c File</i> - Upload decompiled C for hook generation\n"
            "• <i>My Status</i> - Check your permissions and settings\n"
            "• Admin buttons for user management\n\n"
            "⚡ <b>Analysis Features:</b>\n"
            "✅ Parallel processing for speed\n"
            "✅ PATCH_LIB code generation\n"
            "✅ HOOK_LIB with unique functions\n"
            "✅ C file hook analysis\n"
            "✅ No repeated values\n"
            "✅ <b>Dual AI with auto-fallback</b>\n\n"
            "🤖 <b>AI Engines:</b>\n"
            "• Primary: DeepSeek API (fast, reliable)\n"
            "• Fallback: OpenRouter (Kimi-K2 Free)\n"
            "• Automatic failover if one API is down\n\n"
            "⚙️ <b>Owner Commands:</b>\n"
            "• <code>/set_patch &lt;number&gt;</code> - Set PATCH_LIB output limit\n"
            "• <code>/set_hook &lt;number&gt;</code> - Set HOOK_LIB output limit\n\n"
            "📁 <b>Supported Files:</b>\n"
            "• .so (shared object libraries)\n"
            "• .c (decompiled C code)\n\n"
            "📤 <b>Output Formats:</b>\n"
            "• PATCH_LIB(\"lib.so\", \"0x...\", \"bytes\");\n"
            "• HOOK_LIB with function implementations\n"
            "• HOOK_LIB_NO_ORIG for simple hooks"
        )
        
        await query.edit_message_text(
            help_text,
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("« Back to Menu", callback_data="menu_main")
            ]]),
            parse_mode='HTML'
        )
    
    elif data == "menu_analyze_so":
        if not user_manager.is_approved(user_id):
            await query.edit_message_text(
                "❌ <b>Access Denied</b>\n\nYou need approval to analyze files.\nContact the bot owner.",
                reply_markup=InlineKeyboardMarkup([[
                    InlineKeyboardButton("« Back to Menu", callback_data="menu_main")
                ]]),
                parse_mode='HTML'
            )
            return
        
        context.user_data['awaiting_file'] = 'so'
        await query.edit_message_text(
            "📤 <b>Upload .so Library File</b>\n\n"
            "Send a .so file to analyze.\n\n"
            "<b>The bot will:</b>\n"
            "1. Extract binary data with radare2 (parallel)\n"
            "2. Generate PATCH_LIB entries\n"
            "3. Generate HOOK_LIB implementations\n"
            "4. Provide unique, non-repeated code\n\n"
            "🤖 <i>Using dual AI engines for reliability</i>",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("« Cancel", callback_data="menu_main")
            ]]),
            parse_mode='HTML'
        )
    
    elif data == "menu_analyze_c":
        if not user_manager.is_approved(user_id):
            await query.edit_message_text(
                "❌ <b>Access Denied</b>\n\nYou need approval to analyze files.\nContact the bot owner.",
                reply_markup=InlineKeyboardMarkup([[
                    InlineKeyboardButton("« Back to Menu", callback_data="menu_main")
                ]]),
                parse_mode='HTML'
            )
            return
        
        context.user_data['awaiting_file'] = 'c'
        await query.edit_message_text(
            "📄 <b>Upload .c Decompiled File</b>\n\n"
            "Send a .c file (decompiled code) to analyze.\n\n"
            "<b>The bot will:</b>\n"
            "1. Parse all functions from C code\n"
            "2. Generate HOOK_LIB implementations\n"
            "3. Create unique bypass functions\n"
            "4. Provide both hook formats\n\n"
            "🤖 <i>Using dual AI engines for reliability</i>",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("« Cancel", callback_data="menu_main")
            ]]),
            parse_mode='HTML'
        )
    
    elif data == "menu_approve":
        if not (user_manager.is_owner(user_id) or user_manager.is_admin(user_id)):
            await query.answer("❌ No permission", show_alert=True)
            return
        
        context.user_data['action'] = 'approve'
        await query.edit_message_text(
            "👤 <b>Approve User</b>\n\nSend the user ID to approve:",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("« Cancel", callback_data="menu_main")
            ]]),
            parse_mode='HTML'
        )
    
    elif data == "menu_disapprove":
        if not (user_manager.is_owner(user_id) or user_manager.is_admin(user_id)):
            await query.answer("❌ No permission", show_alert=True)
            return
        
        context.user_data['action'] = 'disapprove'
        await query.edit_message_text(
            "🚫 <b>Disapprove User</b>\n\nSend the user ID to disapprove:",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("« Cancel", callback_data="menu_main")
            ]]),
            parse_mode='HTML'
        )
    
    elif data == "menu_add_admin":
        if not user_manager.is_owner(user_id):
            await query.answer("❌ Owner only", show_alert=True)
            return
        
        context.user_data['action'] = 'add_admin'
        await query.edit_message_text(
            "⚡ <b>Add Admin</b>\n\nSend the user ID to make admin:",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("« Cancel", callback_data="menu_main")
            ]]),
            parse_mode='HTML'
        )
    
    elif data == "menu_remove_admin":
        if not user_manager.is_owner(user_id):
            await query.answer("❌ Owner only", show_alert=True)
            return
        
        context.user_data['action'] = 'remove_admin'
        await query.edit_message_text(
            "❌ <b>Remove Admin</b>\n\nSend the user ID to remove from admins:",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("« Cancel", callback_data="menu_main")
            ]]),
            parse_mode='HTML'
        )
    
    elif data == "menu_set_patch":
        if not user_manager.is_owner(user_id):
            await query.answer("❌ Owner only", show_alert=True)
            return
        
        current = config_manager.get_patch_limit()
        context.user_data['action'] = 'set_patch'
        await query.edit_message_text(
            f"⚙️ <b>Set Patch Limit</b>\n\n"
            f"Current limit: <b>{current}</b>\n\n"
            f"Send new limit (1-50):",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("« Cancel", callback_data="menu_main")
            ]]),
            parse_mode='HTML'
        )
    
    elif data == "menu_set_hook":
        if not user_manager.is_owner(user_id):
            await query.answer("❌ Owner only", show_alert=True)
            return
        
        current = config_manager.get_hook_limit()
        context.user_data['action'] = 'set_hook'
        await query.edit_message_text(
            f"⚙️ <b>Set Hook Limit</b>\n\n"
            f"Current limit: <b>{current}</b>\n\n"
            f"Send new limit (1-30):",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("« Cancel", callback_data="menu_main")
            ]]),
            parse_mode='HTML'
        )
    
    elif data == "menu_main":
        welcome_text = "🤖 <b>Main Menu</b>\n\nChoose an option:"
        keyboard = create_main_keyboard(user_id)
        await query.edit_message_text(
            welcome_text,
            reply_markup=keyboard,
            parse_mode='HTML'
        )


async def handle_text_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle text messages for user actions"""
    user_id = update.effective_user.id
    text = update.message.text
    
    action = context.user_data.get('action')
    
    if action:
        try:
            target_id = int(text.strip())
            
            if action == 'approve':
                user_manager.approve_user(target_id)
                await update.message.reply_text(
                    f"✅ User <code>{target_id}</code> has been approved!",
                    parse_mode='HTML'
                )
            elif action == 'disapprove':
                user_manager.disapprove_user(target_id)
                await update.message.reply_text(
                    f"🚫 User <code>{target_id}</code> has been disapproved!",
                    parse_mode='HTML'
                )
            elif action == 'add_admin':
                user_manager.add_admin(target_id)
                await update.message.reply_text(
                    f"⚡ User <code>{target_id}</code> is now an admin!",
                    parse_mode='HTML'
                )
            elif action == 'remove_admin':
                user_manager.remove_admin(target_id)
                await update.message.reply_text(
                    f"❌ User <code>{target_id}</code> removed from admins!",
                    parse_mode='HTML'
                )
            elif action == 'set_patch':
                limit = int(text.strip())
                if limit < 1 or limit > 50:
                    await update.message.reply_text("❌ Limit must be between 1 and 50")
                    return
                config_manager.set_patch_limit(limit)
                await update.message.reply_text(f"✅ Patch limit set to <b>{limit}</b>", parse_mode='HTML')
            elif action == 'set_hook':
                limit = int(text.strip())
                if limit < 1 or limit > 30:
                    await update.message.reply_text("❌ Limit must be between 1 and 30")
                    return
                config_manager.set_hook_limit(limit)
                await update.message.reply_text(f"✅ Hook limit set to <b>{limit}</b>", parse_mode='HTML')
            
            context.user_data.pop('action', None)
            
        except ValueError:
            await update.message.reply_text("❌ Invalid input. Please send a valid number.")


async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle file uploads"""
    user_id = update.effective_user.id
    
    if not user_manager.is_approved(user_id):
        await update.message.reply_text("❌ You need approval to upload files.")
        return
    
    file_type = context.user_data.get('awaiting_file')
    if not file_type:
        await update.message.reply_text("❌ Use the analyze button first.")
        return
    
    document = update.message.document
    file_name = document.file_name
    
    # Validate file extension
    if file_type == 'so' and not file_name.endswith('.so'):
        await update.message.reply_text("❌ Please upload a .so file.")
        return
    elif file_type == 'c' and not file_name.endswith('.c'):
        await update.message.reply_text("❌ Please upload a .c file.")
        return
    
    # Send initial status message with better formatting
    status_msg = await update.message.reply_text(
        "╔═══════════════════════════╗\n"
        "║  🔍 <b>FILE ANALYZER v2.0</b>  ║\n"
        "╚═══════════════════════════╝\n\n"
        f"📥 Downloading <code>{file_name}</code>...\n"
        "⏳ Please wait...\n\n"
        "🤖 <i>AI: Ready for analysis</i>",
        parse_mode='HTML'
    )
    
    file_path = None
    
    try:
        # Download file
        file = await context.bot.get_file(document.file_id)
        file_path = ANALYSIS_DIR / file_name
        await file.download_to_drive(file_path)
        
        if file_type == 'so':
            await process_so_file(status_msg, file_path, file_name)
        elif file_type == 'c':
            await process_c_file(status_msg, file_path, file_name)
    
    except Exception as e:
        logger.error(f"File processing error: {e}")
        
        # Better error message
        error_msg = str(e)
        if "too big" in error_msg.lower():
            error_msg = "File is too large. Telegram bot API limit is 20MB.\n\nPlease try a smaller file or contact the owner."
        
        await status_msg.edit_text(
            "╔═══════════════════════════╗\n"
            "║   ❌ <b>ERROR OCCURRED</b>    ║\n"
            "╚═══════════════════════════╝\n\n"
            f"<b>Error:</b> {error_msg}",
            parse_mode='HTML'
        )
    
    finally:
        # Clean up
        context.user_data.pop('awaiting_file', None)
        if file_path is not None and file_path.exists():
            try:
                file_path.unlink()
            except:
                pass


async def process_so_file(status_msg, file_path: Path, file_name: str):
    """Process .so library file with parallel analysis"""
    
    # Update: Starting analysis
    await status_msg.edit_text(
        "╔═══════════════════════════╗\n"
        "║   🔍 <b>SO ANALYZER</b>       ║\n"
        "╚═══════════════════════════╝\n\n"
        f"✅ Downloaded: <code>{file_name}</code>\n"
        f"📦 Size: <b>{file_path.stat().st_size / 1024 / 1024:.2f} MB</b>\n\n"
        "🔬 Running parallel binary analysis...\n"
        "⏳ Extracting data with radare2...\n\n"
        "🤖 <i>AI engines on standby</i>",
        parse_mode='HTML'
    )
    
    # Perform radare2 analysis (parallel)
    analyzer = Radare2Analyzer(str(file_path))
    analysis_data = await analyzer.analyze_async()
    json_path, txt_path = analyzer.save_analysis()
    
    # Update: Analysis complete, starting AI
    await status_msg.edit_text(
        "╔═══════════════════════════╗\n"
        "║   🔍 <b>SO ANALYZER</b>       ║\n"
        "╚═══════════════════════════╝\n\n"
        f"✅ Binary analysis complete\n"
        f"💾 Data extracted successfully\n\n"
        "🤖 Sending to AI (parallel)...\n"
        "⏳ Generating PATCH_LIB and HOOK_LIB...\n\n"
        "🔵 Primary: DeepSeek\n"
        "🟢 Fallback: OpenRouter",
        parse_mode='HTML'
    )
    
    # Send to AI for parallel analysis
    ai_result = await AIAnalyzer.analyze_with_ai_parallel(file_name, analysis_data)
    
    if ai_result['success']:
        patches = ai_result['patches']
        hooks = ai_result['hooks']
        provider_patches = ai_result.get('provider_patches', 'Unknown')
        provider_hooks = ai_result.get('provider_hooks', 'Unknown')
        
        # Save results
        result_file = ANALYSIS_DIR / f"{file_name}_result.txt"
        with open(result_file, 'w') as f:
            f.write(f"Analysis Result for {file_name}\n")
            f.write(f"{'='*80}\n")
            f.write(f"AI Provider (Patches): {provider_patches}\n")
            f.write(f"AI Provider (Hooks): {provider_hooks}\n")
            f.write(f"{'='*80}\n\n")
            
            f.write(f"PATCH_LIB Entries ({len(patches)}):\n")
            f.write(f"{'-'*80}\n")
            for p in patches:
                f.write(f"{p['code']}\n")
            
            f.write(f"\n\nHOOK_LIB Implementations ({len(hooks)}):\n")
            f.write(f"{'-'*80}\n")
            for h in hooks:
                f.write(f"\n{h['code']}\n")
        
        # Format output message with AI provider info
        patch_display = "\n".join([f"<code>{p['code']}</code>" for p in patches[:10]])
        
        # Show first 2 hook implementations
        hook_display = ""
        for i, h in enumerate(hooks[:3], 1):
            if h['type'] == 'HOOK_LIB':
                code_preview = h['code'][:250] + "..." if len(h['code']) > 250 else h['code']
                hook_display += f"\n{i}. <pre>{code_preview}</pre>\n"
            else:
                hook_display += f"{i}. <code>{h['code']}</code>\n\n"
        
        prev_patches = ai_result['previous_count']['patches']
        prev_hooks = ai_result['previous_count']['hooks']
        
        result_text = (
            "╔═══════════════════════════╗\n"
            "║  ✅ <b>ANALYSIS COMPLETE</b>  ║\n"
            "╚═══════════════════════════╝\n\n"
            f"📱 Library: <code>{file_name}</code>\n"
            f"🔄 Previous patches: {prev_patches}\n"
            f"🔄 Previous hooks: {prev_hooks}\n"
            f"🆕 New patches: <b>{len(patches)}</b>\n"
            f"🆕 New hooks: <b>{len(hooks)}</b>\n\n"
            f"🤖 AI Providers:\n"
            f"  • Patches: <i>{provider_patches}</i>\n"
            f"  • Hooks: <i>{provider_hooks}</i>\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "🔧 <b>PATCH_LIB</b> (first 10):\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"{patch_display}\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "🪝 <b>HOOK_LIB</b> (first 3 samples):\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"{hook_display}\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"📁 Complete file: <code>{result_file.name}</code>\n\n"
            "💡 Downloading full result file..."
        )
        
        # Telegram message limit is 4096 chars
        if len(result_text) > 4000:
            result_text = result_text[:3900] + "\n\n... (truncated, see full file)"
        
        await status_msg.edit_text(result_text, parse_mode='HTML')
        
        # Send the complete file
        try:
            with open(result_file, 'rb') as f:
                await status_msg.reply_document(
                    document=f,
                    filename=result_file.name,
                    caption=f"📄 <b>Complete analysis for {file_name}</b>\n\n"
                            f"✅ {len(patches)} PATCH_LIB entries\n"
                            f"✅ {len(hooks)} HOOK_LIB implementations\n\n"
                            f"🤖 Powered by: {provider_patches} & {provider_hooks}",
                    parse_mode='HTML'
                )
        except Exception as e:
            logger.error(f"Failed to send result file: {e}")
    
    else:
        await status_msg.edit_text(
            "╔═══════════════════════════╗\n"
            "║  ⚠️ <b>ANALYSIS FAILED</b>   ║\n"
            "╚═══════════════════════════╝\n\n"
            f"❌ AI Analysis Error\n\n"
            f"✅ Binary data saved:\n• {Path(json_path).name}\n• {Path(txt_path).name}",
            parse_mode='HTML'
        )


async def process_c_file(status_msg, file_path: Path, file_name: str):
    """Process .c decompiled file"""
    
    # Update: Loading C file
    await status_msg.edit_text(
        "╔═══════════════════════════╗\n"
        "║  📄 <b>C FILE ANALYZER</b>    ║\n"
        "╚═══════════════════════════╝\n\n"
        f"✅ Downloaded: <code>{file_name}</code>\n"
        f"📦 Size: <b>{file_path.stat().st_size / 1024 / 1024:.2f} MB</b>\n\n"
        "📖 Loading C code...\n"
        "⏳ Parsing functions...\n\n"
        "🤖 <i>AI engines ready</i>",
        parse_mode='HTML'
    )
    
    # Load C file
    c_analyzer = CFileAnalyzer(str(file_path))
    content = await c_analyzer.load_content()
    
    # Update: Sending to AI
    await status_msg.edit_text(
        "╔═══════════════════════════╗\n"
        "║  📄 <b>C FILE ANALYZER</b>    ║\n"
        "╚═══════════════════════════╝\n\n"
        f"✅ C code loaded (<b>{len(content):,}</b> bytes)\n\n"
        "🤖 Analyzing with AI...\n"
        "⏳ Generating hook implementations...\n\n"
        "🔵 Primary: DeepSeek\n"
        "🟢 Fallback: OpenRouter",
        parse_mode='HTML'
    )
    
    # Analyze with AI
    ai_result = await AIAnalyzer.analyze_c_file(file_name, content)
    
    if ai_result['success']:
        hooks = ai_result['hooks']
        lib_name = ai_result['lib_name']
        provider = ai_result.get('provider', 'Unknown')
        
        # Save results
        result_file = ANALYSIS_DIR / f"{file_name}_hooks.txt"
        with open(result_file, 'w') as f:
            f.write(f"Hook Analysis for {file_name}\n")
            f.write(f"Library: {lib_name}\n")
            f.write(f"AI Provider: {provider}\n")
            f.write(f"{'='*80}\n\n")
            
            for h in hooks:
                f.write(f"\n{'='*80}\n")
                f.write(f"Address: {h['address']}\n")
                f.write(f"Function: {h['function_name']}\n")
                f.write(f"Type: {h['type']}\n")
                f.write(f"{'='*80}\n")
                f.write(f"{h['code']}\n\n")
        
        # Format output
        hook_display = ""
        complete_shown = 0
        for i, h in enumerate(hooks, 1):
            if complete_shown < 2 and h['type'] == 'HOOK_LIB':
                code_preview = h['code'][:300] + "..." if len(h['code']) > 300 else h['code']
                hook_display += f"\n{i}. {h['address']} - <code>{h['function_name']}</code>\n<pre>{code_preview}</pre>\n"
                complete_shown += 1
            else:
                code_short = h['code'][:80] + "..." if len(h['code']) > 80 else h['code']
                hook_display += f"{i}. <code>{code_short}</code>\n"
        
        prev_count = ai_result['previous_count']
        
        result_text = (
            "╔═══════════════════════════╗\n"
            "║  ✅ <b>HOOKS GENERATED</b>   ║\n"
            "╚═══════════════════════════╝\n\n"
            f"📄 File: <code>{file_name}</code>\n"
            f"📱 Library: <code>{lib_name}</code>\n"
            f"🔄 Previous hooks: {prev_count}\n"
            f"🆕 New hooks: <b>{len(hooks)}</b>\n"
            f"🤖 AI Provider: <i>{provider}</i>\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "🪝 <b>Sample Hooks</b> (first 2 shown):\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"{hook_display}\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"📁 Full implementations: <code>{result_file.name}</code>\n\n"
            "✅ Each hook has unique implementation\n"
            "✅ No repeated patterns"
        )
        
        if len(result_text) > 4000:
            result_text = result_text[:3900] + "\n\n... (see full file)"
        
        await status_msg.edit_text(result_text, parse_mode='HTML')
        
        # Send the file
        try:
            with open(result_file, 'rb') as f:
                await status_msg.reply_document(
                    document=f,
                    filename=result_file.name,
                    caption=f"📄 <b>Complete hook implementations for {lib_name}</b>\n\n"
                            f"Contains {len(hooks)} unique hooks with full code.\n\n"
                            f"🤖 Powered by: {provider}",
                    parse_mode='HTML'
                )
        except Exception as e:
            logger.error(f"Failed to send file: {e}")
    
    else:
        error_msg = ai_result.get('error', 'Unknown error')
        await status_msg.edit_text(
            "╔═══════════════════════════╗\n"
            "║  ⚠️ <b>ANALYSIS FAILED</b>   ║\n"
            "╚═══════════════════════════╝\n\n"
            f"❌ <b>Error:</b> {error_msg}\n\n"
            "💡 Both AI engines failed. Please try again later.",
            parse_mode='HTML'
        )


def main():
    """Start the bot"""
    logger.info("=" * 80)
    logger.info("Starting Advanced SO & C File Analyzer Bot v2.0...")
    logger.info("=" * 80)
    logger.info(f"Script directory: {SCRIPT_DIR}")
    logger.info(f"Analysis results directory: {ANALYSIS_DIR}")
    logger.info(f"Patch limit: {config_manager.get_patch_limit()}")
    logger.info(f"Hook limit: {config_manager.get_hook_limit()}")
    logger.info("AI Engines: DeepSeek (Primary) + OpenRouter (Fallback)")
    logger.info("=" * 80)
    
    # Check if radare2 is available
    try:
        r2_version = subprocess.run(['r2', '-v'], capture_output=True, text=True)
        logger.info(f"✅ Radare2 version: {r2_version.stdout.strip()}")
    except FileNotFoundError:
        logger.error("❌ Radare2 not found! Please install with: sudo apt-get install radare2")
        return
    
    # Create application
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    
    # Add handlers
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("set_patch", set_patch_command))
    application.add_handler(CommandHandler("set_hook", set_hook_command))
    application.add_handler(CallbackQueryHandler(button_handler))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text_message))
    application.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    
    # Start bot
    logger.info("✅ Bot is running... Press Ctrl+C to stop.")
    logger.info("=" * 80)
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
