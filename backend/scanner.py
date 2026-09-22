"""
HarvestGuard Static Analysis Scanner Module
Detects quantum-vulnerable cryptography usage across Python, JavaScript, Java, and configuration files.
"""

from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional, Set
import os
import ast
import re
from pathlib import Path


@dataclass
class Finding:
    file_path: str
    line_number: int
    code_snippet: str
    vulnerability_type: str  # RSA, ECC, DH, weak-TLS-config
    severity: str            # high, medium, low
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanSummary:
    total: int
    high: int
    medium: int
    low: int
    by_type: Dict[str, int]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PythonAstScanner(ast.NodeVisitor):
    """
    AST-based scanner for Python files.
    Avoids false positives from comments and docstrings.
    """

    def __init__(self, file_path: str, source_code: str):
        self.file_path = file_path
        self.source_code = source_code
        self.lines = source_code.splitlines()
        self.findings: List[Finding] = []
        self.seen_lines: Set[(int, str)] = set()

    def _get_line(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1].strip()
        return ""

    def _add_finding(
        self,
        lineno: int,
        vuln_type: str,
        severity: str,
        description: str,
        custom_snippet: Optional[str] = None,
    ):
        key = (lineno, vuln_type)
        if key in self.seen_lines:
            return
        self.seen_lines.add(key)
        snippet = custom_snippet or self._get_line(lineno)
        self.findings.append(
            Finding(
                file_path=self.file_path,
                line_number=lineno,
                code_snippet=snippet,
                vulnerability_type=vuln_type,
                severity=severity,
                description=description,
            )
        )

    def _get_attribute_chain(self, node: ast.AST) -> List[str]:
        chain = []
        curr = node
        while isinstance(curr, ast.Attribute):
            chain.append(curr.attr)
            curr = curr.value
        if isinstance(curr, ast.Name):
            chain.append(curr.id)
        chain.reverse()
        return chain

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            name = alias.name
            if name == "ecdsa" or name.startswith("ecdsa."):
                self._add_finding(
                    node.lineno,
                    "ECC",
                    "low",
                    f"Bare import of vulnerable ECC library '{name}'",
                )
            elif name == "rsa" or name.startswith("rsa."):
                self._add_finding(
                    node.lineno,
                    "RSA",
                    "low",
                    f"Bare import of vulnerable RSA library '{name}'",
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ""
        # Check RSA imports
        if "Crypto.PublicKey.RSA" in module or module == "Crypto.PublicKey" or module.endswith(".rsa"):
            for alias in node.names:
                if alias.name.upper() == "RSA" or "generate" in alias.name:
                    self._add_finding(
                        node.lineno,
                        "RSA",
                        "low",
                        f"Bare import of RSA primitive '{alias.name}' from '{module}'",
                    )
        elif module.startswith("cryptography.hazmat.primitives.asymmetric"):
            for alias in node.names:
                if alias.name == "rsa":
                    self._add_finding(
                        node.lineno,
                        "RSA",
                        "low",
                        f"Bare import of classical asymmetric module '{alias.name}'",
                    )
                elif alias.name in ("ec", "SECP256K1", "SECP256R1"):
                    self._add_finding(
                        node.lineno,
                        "ECC",
                        "low",
                        f"Bare import of ECC primitive '{alias.name}'",
                    )
                elif alias.name == "dh":
                    self._add_finding(
                        node.lineno,
                        "DH",
                        "low",
                        f"Bare import of Diffie-Hellman module '{alias.name}'",
                    )
        elif "ecdsa" in module:
            self._add_finding(
                node.lineno,
                "ECC",
                "low",
                f"Bare import of ECDSA primitives from '{module}'",
            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        chain = self._get_attribute_chain(node.func)
        full_call = ".".join(chain)

        # 1. RSA Key Generation (High)
        if (
            full_call in (
                "Crypto.PublicKey.RSA.generate",
                "RSA.generate",
                "rsa.generate_private_key",
                "generate_private_key",
            )
            and ("RSA" in full_call or "rsa" in full_call)
        ):
            self._add_finding(
                node.lineno,
                "RSA",
                "high",
                "Quantum-vulnerable RSA key generation call detected",
            )
        elif full_call.endswith(".generate_private_key") and "rsa" in full_call.lower():
            self._add_finding(
                node.lineno,
                "RSA",
                "high",
                "Quantum-vulnerable RSA generate_private_key call detected",
            )

        # 2. ECC Key Generation / Curve instantiation (High)
        elif (
            full_call.endswith(".generate_private_key")
            and ("ec" in chain or any("SECP" in str(arg) for arg in node.args))
        ) or full_call in ("ec.generate_private_key", "ec.SECP256K1", "ec.SECP256R1", "SECP256K1", "SECP256R1"):
            self._add_finding(
                node.lineno,
                "ECC",
                "high",
                f"Quantum-vulnerable ECC operation/key generation '{full_call}' detected",
            )

        # 3. Diffie-Hellman Calls (High)
        elif (
            full_call in ("dh.generate_parameters", "generate_parameters")
            or (full_call.endswith(".generate_parameters") and "dh" in full_call.lower())
            or (full_call.endswith(".generate_private_key") and "dh" in full_call.lower())
        ):
            self._add_finding(
                node.lineno,
                "DH",
                "high",
                "Quantum-vulnerable Diffie-Hellman parameter/key generation call detected",
            )

        # 4. Cryptographic Operations: Signing / Verification / Encryption / Decryption (Medium)
        func_name = chain[-1] if chain else ""
        if func_name in ("sign", "verify", "encrypt", "decrypt", "exchange"):
            # Check context / arguments to determine algorithm
            call_source = self._get_line(node.lineno)
            if any(term in call_source for term in ("padding.PSS", "padding.PKCS1v15", "padding.OAEP", "rsa", "RSA")):
                self._add_finding(
                    node.lineno,
                    "RSA",
                    "medium",
                    f"RSA cryptographic operation '{func_name}' detected",
                )
            elif any(term in call_source for term in ("ec.ECDSA", "ECDSA", "ecdsa", "SECP", "secp")):
                self._add_finding(
                    node.lineno,
                    "ECC",
                    "medium",
                    f"ECC cryptographic operation '{func_name}' detected",
                )
            elif func_name == "exchange" or "dh" in call_source.lower():
                self._add_finding(
                    node.lineno,
                    "DH",
                    "medium",
                    f"Diffie-Hellman key exchange operation '{func_name}' detected",
                )

        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        # Catch direct references to known vulnerable curves if not already visited in Call
        if node.attr in ("SECP256K1", "SECP256R1", "secp256k1", "secp256r1", "NISTP256", "NISTP384"):
            self._add_finding(
                node.lineno,
                "ECC",
                "high",
                f"Reference to classical elliptic curve '{node.attr}'",
            )
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name):
        if node.id in ("SECP256K1", "SECP256R1"):
            self._add_finding(
                node.lineno,
                "ECC",
                "high",
                f"Reference to classical elliptic curve identifier '{node.id}'",
            )
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant):
        # Inspect string constants for weak TLS configurations
        if isinstance(node.value, str):
            if re.search(r"TLS_RSA_[A-Z0-9_]+", node.value):
                self._add_finding(
                    node.lineno,
                    "weak-TLS-config",
                    "medium",
                    f"Weak TLS cipher suite specified: '{node.value}'",
                )
            elif re.search(r"TLS_ECDHE_[A-Z0-9_]+", node.value):
                self._add_finding(
                    node.lineno,
                    "weak-TLS-config",
                    "medium",
                    f"Quantum-vulnerable TLS cipher suite specified: '{node.value}'",
                )
        self.generic_visit(node)


class RegexCodeScanner:
    """
    Regex-based pattern scanner for JavaScript/TypeScript, Java, and Configuration files.
    """

    JAVA_PATTERNS = [
        # RSA
        (
            re.compile(r'KeyPairGenerator\.getInstance\s*\(\s*["\']RSA["\']\)', re.IGNORECASE),
            "RSA",
            "high",
            "Java RSA KeyPairGenerator instance detected",
        ),
        (
            re.compile(r'Cipher\.getInstance\s*\(\s*["\']RSA', re.IGNORECASE),
            "RSA",
            "medium",
            "Java RSA Cipher operation detected",
        ),
        (
            re.compile(r'Signature\.getInstance\s*\(\s*["\'][^"\']*RSA', re.IGNORECASE),
            "RSA",
            "medium",
            "Java RSA Signature verification/signing operation detected",
        ),
        (
            re.compile(r'import\s+java\.security\.interfaces\.RSA(?:Private|Public)Key;', re.IGNORECASE),
            "RSA",
            "low",
            "Bare import of Java RSA key interface",
        ),

        # ECC
        (
            re.compile(r'KeyPairGenerator\.getInstance\s*\(\s*["\'](?:EC|ECDSA)["\']\)', re.IGNORECASE),
            "ECC",
            "high",
            "Java EC/ECDSA KeyPairGenerator instance detected",
        ),
        (
            re.compile(r'ECGenParameterSpec\s*\(\s*["\'](?:secp256[rk]1|prime256v1)["\']\)', re.IGNORECASE),
            "ECC",
            "high",
            "Java EC curve specification detected",
        ),
        (
            re.compile(r'Signature\.getInstance\s*\(\s*["\'][^"\']*(?:ECDSA|SHA\d+withECDSA)["\']\)', re.IGNORECASE),
            "ECC",
            "medium",
            "Java ECDSA Signature operation detected",
        ),
        (
            re.compile(r'import\s+java\.security\.interfaces\.EC(?:Private|Public)Key;', re.IGNORECASE),
            "ECC",
            "low",
            "Bare import of Java EC key interface",
        ),

        # DH
        (
            re.compile(r'KeyAgreement\.getInstance\s*\(\s*["\'](?:DH|DiffieHellman)["\']\)', re.IGNORECASE),
            "DH",
            "high",
            "Java Diffie-Hellman KeyAgreement instance detected",
        ),
        (
            re.compile(r'KeyPairGenerator\.getInstance\s*\(\s*["\'](?:DH|DiffieHellman)["\']\)', re.IGNORECASE),
            "DH",
            "high",
            "Java Diffie-Hellman KeyPairGenerator instance detected",
        ),
        (
            re.compile(r'\.generateSecret\s*\(', re.IGNORECASE),
            "DH",
            "medium",
            "Diffie-Hellman shared secret generation detected",
        ),

        # Weak TLS
        (
            re.compile(r'TLS_RSA_[A-Z0-9_]+'),
            "weak-TLS-config",
            "medium",
            "Weak RSA-based TLS cipher suite in Java code",
        ),
        (
            re.compile(r'TLS_ECDHE_[A-Z0-9_]+'),
            "weak-TLS-config",
            "medium",
            "Quantum-vulnerable ECDHE-based TLS cipher suite in Java code",
        ),
    ]

    JS_PATTERNS = [
        # RSA
        (
            re.compile(r'crypto\.generateKeyPair(?:Sync)?\s*\(\s*["\']rsa["\']', re.IGNORECASE),
            "RSA",
            "high",
            "Node.js crypto RSA key pair generation detected",
        ),
        (
            re.compile(r'crypto\.createSign\s*\(\s*["\'][^"\']*RSA', re.IGNORECASE),
            "RSA",
            "medium",
            "Node.js RSA signing operation detected",
        ),
        (
            re.compile(r'crypto\.createVerify\s*\(\s*["\'][^"\']*RSA', re.IGNORECASE),
            "RSA",
            "medium",
            "Node.js RSA verification operation detected",
        ),
        (
            re.compile(r'(?:require\s*\(\s*["\']node-rsa["\']\)|from\s+["\']node-rsa["\'])', re.IGNORECASE),
            "RSA",
            "low",
            "Bare import of node-rsa library",
        ),

        # ECC
        (
            re.compile(r'crypto\.generateKeyPair(?:Sync)?\s*\(\s*["\']ec["\']', re.IGNORECASE),
            "ECC",
            "high",
            "Node.js crypto EC key pair generation detected",
        ),
        (
            re.compile(r'new\s+elliptic\.ec\s*\(|ec\.keyFromPrivate', re.IGNORECASE),
            "ECC",
            "high",
            "Elliptic library ECC key/curve instantiation detected",
        ),
        (
            re.compile(r'crypto\.createECDH\s*\(', re.IGNORECASE),
            "ECC",
            "high",
            "Node.js crypto createECDH call detected",
        ),
        (
            re.compile(r'["\'](?:secp256k1|secp256r1|prime256v1)["\']', re.IGNORECASE),
            "ECC",
            "high",
            "Classical elliptic curve specification detected",
        ),
        (
            re.compile(r'crypto\.createSign\s*\(\s*["\'][^"\']*(?:ECDSA|SHA256withECDSA)["\']', re.IGNORECASE),
            "ECC",
            "medium",
            "Node.js ECDSA signing operation detected",
        ),
        (
            re.compile(r'(?:require\s*\(\s*["\']elliptic["\']\)|from\s+["\']elliptic["\'])', re.IGNORECASE),
            "ECC",
            "low",
            "Bare import of elliptic library",
        ),

        # DH
        (
            re.compile(r'crypto\.createDiffieHellman(?:Group)?\s*\(', re.IGNORECASE),
            "DH",
            "high",
            "Node.js Diffie-Hellman key exchange creation detected",
        ),
        (
            re.compile(r'\.computeSecret\s*\(', re.IGNORECASE),
            "DH",
            "medium",
            "Diffie-Hellman secret computation detected",
        ),

        # Weak TLS
        (
            re.compile(r'TLS_RSA_[A-Z0-9_]+'),
            "weak-TLS-config",
            "medium",
            "Weak RSA TLS cipher suite configured in JavaScript",
        ),
        (
            re.compile(r'TLS_ECDHE_[A-Z0-9_]+'),
            "weak-TLS-config",
            "medium",
            "Quantum-vulnerable ECDHE TLS cipher suite configured in JavaScript",
        ),
    ]

    CONFIG_PATTERNS = [
        (
            re.compile(r'TLS_RSA_[A-Z0-9_]+'),
            "weak-TLS-config",
            "medium",
            "Weak RSA-based TLS cipher suite specified in configuration",
        ),
        (
            re.compile(r'TLS_ECDHE_[A-Z0-9_]+'),
            "weak-TLS-config",
            "medium",
            "Quantum-vulnerable ECDHE cipher suite specified in configuration",
        ),
    ]

    @classmethod
    def scan_text(
        cls,
        file_path: str,
        content: str,
        patterns: List[tuple],
    ) -> List[Finding]:
        findings = []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            # Skip single-line comments in JS/Java to reduce noise
            if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                continue
            for regex, vuln_type, severity, description in patterns:
                if regex.search(line):
                    findings.append(
                        Finding(
                            file_path=file_path,
                            line_number=idx,
                            code_snippet=stripped,
                            vulnerability_type=vuln_type,
                            severity=severity,
                            description=description,
                        )
                    )
                    break
        return findings


class CodebaseScanner:
    """
    Orchestrates AST and Regex scanning across an entire codebase or folder.
    """

    EXCLUDE_DIRS = {
        ".git",
        "node_modules",
        "venv",
        ".venv",
        "__pycache__",
        ".next",
        "dist",
        "build",
        "out",
        "target",
        ".idea",
        ".vscode",
    }

    PYTHON_EXTENSIONS = {".py"}
    JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
    JAVA_EXTENSIONS = {".java"}
    CONFIG_EXTENSIONS = {
        ".conf",
        ".yaml",
        ".yml",
        ".json",
        ".properties",
        ".ini",
        ".env",
        ".toml",
        ".xml",
    }

    def scan_file(self, file_path: str, rel_path: Optional[str] = None) -> List[Finding]:
        display_path = rel_path or file_path
        ext = os.path.splitext(file_path)[1].lower()

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return []

        if ext in self.PYTHON_EXTENSIONS:
            try:
                tree = ast.parse(content, filename=file_path)
                visitor = PythonAstScanner(display_path, content)
                visitor.visit(tree)
                return visitor.findings
            except SyntaxError:
                # If syntax error in python file, return empty or fallback
                return []
        elif ext in self.JAVA_EXTENSIONS:
            return RegexCodeScanner.scan_text(display_path, content, RegexCodeScanner.JAVA_PATTERNS)
        elif ext in self.JS_EXTENSIONS:
            return RegexCodeScanner.scan_text(display_path, content, RegexCodeScanner.JS_PATTERNS)
        elif ext in self.CONFIG_EXTENSIONS:
            return RegexCodeScanner.scan_text(display_path, content, RegexCodeScanner.CONFIG_PATTERNS)

        return []

    def scan_directory(self, root_dir: str) -> Dict[str, Any]:
        findings: List[Finding] = []
        files_scanned = 0

        for root, dirs, files in os.walk(root_dir):
            # Prune excluded directories
            dirs[:] = [d for d in dirs if d not in self.EXCLUDE_DIRS]

            for file in files:
                ext = os.path.splitext(file)[1].lower()
                all_exts = (
                    self.PYTHON_EXTENSIONS
                    | self.JS_EXTENSIONS
                    | self.JAVA_EXTENSIONS
                    | self.CONFIG_EXTENSIONS
                )
                if ext in all_exts:
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, root_dir).replace("\\", "/")
                    file_findings = self.scan_file(full_path, rel_path)
                    findings.extend(file_findings)
                    files_scanned += 1

        # Calculate summary counts
        summary = self.calculate_summary(findings)

        return {
            "status": "completed",
            "files_scanned": files_scanned,
            "summary": summary.to_dict(),
            "findings": [f.to_dict() for f in findings],
        }

    def scan_code_snippet(self, code_snippet: str, language: str = "python") -> Dict[str, Any]:
        findings: List[Finding] = []
        lang = language.lower()

        if lang in ("python", "py"):
            try:
                tree = ast.parse(code_snippet, filename="<snippet>")
                visitor = PythonAstScanner("<inline_snippet>", code_snippet)
                visitor.visit(tree)
                findings = visitor.findings
            except SyntaxError:
                findings = []
        elif lang in ("javascript", "js", "typescript", "ts"):
            findings = RegexCodeScanner.scan_text(
                "<inline_snippet>", code_snippet, RegexCodeScanner.JS_PATTERNS
            )
        elif lang in ("java",):
            findings = RegexCodeScanner.scan_text(
                "<inline_snippet>", code_snippet, RegexCodeScanner.JAVA_PATTERNS
            )
        else:
            findings = RegexCodeScanner.scan_text(
                "<inline_snippet>", code_snippet, RegexCodeScanner.CONFIG_PATTERNS
            )

        summary = self.calculate_summary(findings)
        return {
            "status": "completed",
            "files_scanned": 1,
            "summary": summary.to_dict(),
            "findings": [f.to_dict() for f in findings],
        }

    @staticmethod
    def calculate_summary(findings: List[Finding]) -> ScanSummary:
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")

        by_type: Dict[str, int] = {
            "RSA": 0,
            "ECC": 0,
            "DH": 0,
            "weak-TLS-config": 0,
        }
        for f in findings:
            if f.vulnerability_type in by_type:
                by_type[f.vulnerability_type] += 1
            else:
                by_type[f.vulnerability_type] = 1

        return ScanSummary(
            total=len(findings),
            high=high,
            medium=medium,
            low=low,
            by_type=by_type,
        )
