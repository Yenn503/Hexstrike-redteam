"""
BOAZ Manager - Integration layer for BOAZ evasion framework
Handles payload generation, validation, and analysis
"""

import os
import subprocess
import logging
import math
from collections import Counter
from typing import Dict, Any, Optional
from pathlib import Path

from .loader_reference import LOADER_REFERENCE
from .encoder_reference import ENCODING_REFERENCE

logger = logging.getLogger(__name__)


class BOAZManager:
    """Manager class for BOAZ evasion framework integration"""

    # Security constants
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
    SUBPROCESS_TIMEOUT = 300  # 5 minutes

    # Valid parameter values
    VALID_ENCODINGS = ["uuid", "xor", "mac", "ipv4", "base45", "base64",
                       "base58", "aes", "des", "chacha", "rc4", "aes2"]
    VALID_COMPILERS = ["mingw", "pluto", "akira"]
    VALID_SHELLCODE_TYPES = ["donut", "pe2sh", "rc4", "amber", "shoggoth", "augment"]

    def __init__(self, boaz_path: Optional[str] = None):
        """
        Initialize BOAZ Manager

        Args:
            boaz_path: Path to BOAZ_beta directory (defaults to environment variable)
        """
        self.boaz_path = boaz_path or os.getenv("BOAZ_PATH")

        if not self.boaz_path:
            # Default to BOAZ_beta in hexstrike-ai directory
            current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.boaz_path = os.path.join(current_dir, "BOAZ_beta")

        self.boaz_path = os.path.abspath(self.boaz_path)
        self.boaz_script = os.path.join(self.boaz_path, "Boaz.py")

        if not os.path.exists(self.boaz_script):
            logger.warning(f"Boaz.py not found at {self.boaz_script}")
            logger.warning("BOAZ tools will not be available until BOAZ_PATH is configured")

    def _validate_path(self, path: str, must_exist: bool = False) -> str:
        """
        Validate file paths to prevent traversal attacks

        Args:
            path: Path to validate
            must_exist: Whether the path must exist

        Returns:
            Validated absolute path

        Raises:
            ValueError: If path is invalid
            FileNotFoundError: If must_exist=True and file doesn't exist
        """
        logger.debug(f"Validating path: {path}")

        # Reject path traversal patterns
        if ".." in path:
            logger.warning(f"Path traversal detected: {path}")
            raise ValueError("Path traversal not allowed")

        # Reject absolute paths (force relative to BOAZ_PATH)
        if os.path.isabs(path):
            logger.warning(f"Absolute path rejected: {path}")
            raise ValueError("Absolute paths not allowed, use paths relative to BOAZ_PATH")

        # Make path relative to BOAZ_PATH
        safe_path = os.path.join(self.boaz_path, path)
        safe_path = os.path.abspath(safe_path)

        # Ensure it's still within BOAZ_PATH
        if not safe_path.startswith(self.boaz_path):
            logger.warning(f"Path outside BOAZ_PATH: {safe_path}")
            raise ValueError("Path must be within BOAZ_PATH directory")

        if must_exist and not os.path.exists(safe_path):
            logger.error(f"File not found: {safe_path}")
            raise FileNotFoundError(f"File not found: {path}")

        logger.debug(f"Path validated: {safe_path}")
        return safe_path

    def _validate_loader(self, loader: int) -> None:
        """Validate loader number"""
        if not isinstance(loader, int):
            raise ValueError(f"Loader must be an integer, got {type(loader)}")

        if loader < 1 or loader > 77:
            raise ValueError(f"Invalid loader: {loader}. Must be between 1-77")

        logger.debug(f"Loader validated: {loader}")

    def _validate_encoding(self, encoding: str) -> None:
        """Validate encoding type"""
        if encoding not in self.VALID_ENCODINGS:
            raise ValueError(f"Invalid encoding: {encoding}. Valid options: {', '.join(self.VALID_ENCODINGS)}")

        logger.debug(f"Encoding validated: {encoding}")

    def _validate_compiler(self, compiler: str) -> None:
        """Validate compiler choice"""
        if compiler not in self.VALID_COMPILERS:
            raise ValueError(f"Invalid compiler: {compiler}. Valid options: {', '.join(self.VALID_COMPILERS)}")

        logger.debug(f"Compiler validated: {compiler}")

    def _validate_shellcode_type(self, shellcode_type: str) -> None:
        """Validate shellcode type"""
        if shellcode_type not in self.VALID_SHELLCODE_TYPES:
            raise ValueError(f"Invalid shellcode type: {shellcode_type}. Valid options: {', '.join(self.VALID_SHELLCODE_TYPES)}")

        logger.debug(f"Shellcode type validated: {shellcode_type}")

    def _check_file_size(self, path: str) -> None:
        """Check file size is within limits"""
        if not os.path.exists(path):
            return  # Will be caught by other validation

        size = os.path.getsize(path)
        if size > self.MAX_FILE_SIZE:
            logger.error(f"File too large: {size} bytes (max {self.MAX_FILE_SIZE})")
            raise ValueError(f"File too large: {size} bytes (max {self.MAX_FILE_SIZE} bytes / {self.MAX_FILE_SIZE // (1024*1024)}MB)")

        logger.debug(f"File size OK: {size} bytes")

    def _sanitize_string(self, value: str, param_name: str) -> str:
        """Sanitize string inputs to prevent injection"""
        dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '<', '>', '\n', '\r']
        for char in dangerous_chars:
            if char in value:
                logger.warning(f"Dangerous character '{char}' found in {param_name}")
                raise ValueError(f"Invalid character '{char}' in {param_name}")
        return value

    def generate_payload(self, args: dict) -> dict:
        """
        Generate evasive payload using BOAZ

        Args:
            args: Dictionary with payload generation parameters

        Returns:
            dict: Result with success status and output information
        """
        logger.info(f"Generating payload: {args.get('input_file')} -> {args.get('output_file')}")

        # Check if BOAZ is available
        if not os.path.exists(self.boaz_script):
            return {
                "success": False,
                "error": f"BOAZ framework not found at {self.boaz_script}. Please set BOAZ_PATH environment variable."
            }

        # Validate and sanitize paths
        input_file = self._validate_path(args["input_file"], must_exist=True)
        output_file = self._validate_path(args["output_file"], must_exist=False)

        # Check input file size
        self._check_file_size(input_file)

        # Validate optional parameters
        if "loader" in args:
            self._validate_loader(args["loader"])
        if "encoding" in args:
            self._validate_encoding(args["encoding"])
        if "compiler" in args:
            self._validate_compiler(args["compiler"])
        if "shellcode_type" in args:
            self._validate_shellcode_type(args["shellcode_type"])

        # Sanitize string parameters
        if "sign_certificate" in args:
            args["sign_certificate"] = self._sanitize_string(args["sign_certificate"], "sign_certificate")
        if "mllvm" in args:
            args["mllvm"] = self._sanitize_string(args["mllvm"], "mllvm")
        if "binder" in args:
            binder_path = self._validate_path(args["binder"], must_exist=False)
            args["binder"] = binder_path

        cmd = ["python3", self.boaz_script]

        # Required arguments (use validated paths)
        cmd.extend(["-f", input_file])
        cmd.extend(["-o", output_file])

        # Optional arguments
        if "loader" in args:
            cmd.extend(["-l", str(args["loader"])])
        if "encoding" in args:
            cmd.extend(["-e", args["encoding"]])
        if "compiler" in args:
            cmd.extend(["-c", args["compiler"]])
        if "shellcode_type" in args:
            cmd.extend(["-t", args["shellcode_type"]])

        # Boolean flags
        if args.get("obfuscate"):
            cmd.append("-obf")
        if args.get("obfuscate_api"):
            cmd.append("-obf_api")
        if args.get("anti_emulation"):
            cmd.append("-a")
        if args.get("sleep"):
            cmd.append("-sleep")
        if args.get("etw"):
            cmd.append("-etw")
        if args.get("api_unhooking"):
            cmd.append("-u")
        if args.get("god_speed"):
            cmd.append("-g")
        if args.get("cfg"):
            cmd.append("-cfg")
        if args.get("self_deletion"):
            cmd.append("-d")
        if args.get("anti_forensic"):
            cmd.append("-af")
        if args.get("dll"):
            cmd.append("-dll")
        if args.get("cpl"):
            cmd.append("-cpl")

        # Integer options
        if "dream" in args:
            cmd.extend(["-dream", str(args["dream"])])
        if "entropy" in args:
            cmd.extend(["-entropy", str(args["entropy"])])
        if "syswhisper" in args:
            cmd.extend(["-w", str(args["syswhisper"])])

        # String options
        if "sign_certificate" in args:
            cmd.extend(["-s", args["sign_certificate"]])
        if "mllvm" in args:
            cmd.extend(["-mllvm", args["mllvm"]])
        if "binder" in args:
            cmd.extend(["-b", args["binder"]])

        # Additional boolean flags
        if args.get("sgn_encode"):
            cmd.append("-sgn")
        if args.get("stardust"):
            cmd.append("-sd")
        if args.get("junk_api"):
            cmd.append("-j")
        if args.get("watermark"):
            cmd.append("-wm")
        if args.get("icon"):
            cmd.append("-icon")
        if args.get("detect_hooks"):
            cmd.append("-dh")
        if args.get("divide"):
            cmd.append("-divide")

        # Execute with timeout
        try:
            logger.info(f"Executing BOAZ command: {' '.join(cmd[:5])}...")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.boaz_path,
                timeout=self.SUBPROCESS_TIMEOUT
            )

            output = f"STDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}"
            if result.returncode == 0:
                logger.info(f"Payload generated successfully: {args['output_file']}")

                # Check if output file was actually created
                if os.path.exists(output_file):
                    file_size = os.path.getsize(output_file)
                    return {
                        "success": True,
                        "output_path": output_file,
                        "file_size": file_size,
                        "loader": args.get('loader', 'default'),
                        "encoding": args.get('encoding', 'none'),
                        "compiler": args.get('compiler', 'mingw'),
                        "stdout": result.stdout,
                        "stderr": result.stderr,
                        "message": f"✅ Payload generated successfully at {output_file}"
                    }
                else:
                    return {
                        "success": False,
                        "error": f"BOAZ reported success but output file not found at {output_file}",
                        "stdout": result.stdout,
                        "stderr": result.stderr
                    }
            else:
                logger.error(f"Payload generation failed with exit code {result.returncode}")
                return {
                    "success": False,
                    "error": f"BOAZ execution failed (exit code {result.returncode})",
                    "stdout": result.stdout,
                    "stderr": result.stderr
                }

        except subprocess.TimeoutExpired:
            logger.error(f"Payload generation timed out after {self.SUBPROCESS_TIMEOUT} seconds")
            return {
                "success": False,
                "error": f"Operation timed out after {self.SUBPROCESS_TIMEOUT} seconds"
            }
        except Exception as e:
            logger.exception("Unexpected error during payload generation")
            return {
                "success": False,
                "error": f"Unexpected error: {str(e)}"
            }

    def list_loaders(self, category: str = "all") -> dict:
        """List available loaders"""
        loaders = LOADER_REFERENCE

        if category != "all":
            loaders = {k: v for k, v in loaders.items()
                      if v.get("category") == category}

        output = "# BOAZ Loaders\n\n"
        for num, info in sorted(loaders.items()):
            output += f"**Loader {num}**: {info['name']}\n"
            output += f"  Category: {info['category']}\n"
            output += f"  Description: {info['description']}\n"
            if info.get("encoding_required"):
                output += f"  Required Encoding: {info['encoding_required']}\n"
            output += "\n"

        return {
            "success": True,
            "loaders": loaders,
            "output": output,
            "count": len(loaders)
        }

    def list_encoders(self) -> dict:
        """List encoding schemes"""
        encoders = ENCODING_REFERENCE

        output = "# BOAZ Encoding Schemes\n\n"
        for name, info in encoders.items():
            output += f"**{name}**: {info['description']}\n"
            output += f"  Strength: {info['strength']}\n"
            output += f"  Speed: {info['speed']}\n"
            output += f"  Use case: {info['use_case']}\n\n"

        return {
            "success": True,
            "encoders": encoders,
            "output": output,
            "count": len(encoders)
        }

    def analyze_binary(self, file_path: str) -> dict:
        """Analyze binary file"""
        logger.info(f"Analyzing binary: {file_path}")

        # Validate and sanitize path
        file_path = self._validate_path(file_path, must_exist=True)

        # Check file size before reading
        self._check_file_size(file_path)

        # Basic analysis
        size = os.path.getsize(file_path)

        # Read file and calculate entropy
        with open(file_path, "rb") as f:
            data = f.read()

        # Shannon entropy calculation
        counter = Counter(data)
        entropy = 0
        for count in counter.values():
            p = count / len(data)
            entropy -= p * math.log2(p)

        output = f"# Binary Analysis: {file_path}\n\n"
        output += f"📁 Size: {size} bytes ({size/1024:.2f} KB)\n"
        output += f"📊 Entropy: {entropy:.4f} (0-8 scale)\n\n"

        if entropy > 7.5:
            output += "🔴 HIGH ENTROPY - Likely encrypted/packed\n"
            recommendation = "Use -entropy 1 or 2 to reduce entropy"
        elif entropy > 6.5:
            output += "🟡 MEDIUM ENTROPY - May trigger heuristics\n"
            recommendation = "Consider entropy reduction if detected"
        else:
            output += "🟢 LOW ENTROPY - Good for evasion\n"
            recommendation = "Entropy is acceptable"

        output += f"\n💡 Recommendation: {recommendation}"

        logger.info(f"Binary analysis complete: {file_path}, entropy={entropy:.4f}")

        return {
            "success": True,
            "file_path": file_path,
            "size": size,
            "entropy": entropy,
            "output": output,
            "recommendation": recommendation
        }

    def validate_options(self, loader: Optional[int] = None,
                        encoding: Optional[str] = None,
                        compiler: Optional[str] = None) -> dict:
        """Validate configuration"""
        issues = []

        # Validate loader
        if loader is not None:
            if loader not in LOADER_REFERENCE:
                issues.append(f"Loader {loader} not found")
            else:
                loader_info = LOADER_REFERENCE[loader]
                if encoding and loader_info.get("encoding_required"):
                    if encoding != loader_info["encoding_required"]:
                        issues.append(
                            f"Loader {loader} requires encoding: "
                            f"{loader_info['encoding_required']}"
                        )

        # Validate encoding
        if encoding is not None:
            if encoding not in ENCODING_REFERENCE:
                issues.append(f"Unknown encoding: {encoding}")

        # Validate compiler
        if compiler is not None:
            if compiler not in self.VALID_COMPILERS:
                issues.append(f"Unknown compiler: {compiler}")

        if issues:
            output = "❌ Validation Failed:\n\n" + "\n".join(f"- {issue}" for issue in issues)
            success = False
        else:
            output = "✅ Configuration valid"
            success = True

        return {
            "success": success,
            "output": output,
            "issues": issues
        }
