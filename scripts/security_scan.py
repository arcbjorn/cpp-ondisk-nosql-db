#!/usr/bin/env python3
"""
IshikuraDB（石蔵） Security Vulnerability Scanner

This script performs automated security scanning for common vulnerabilities
in the IshikuraDB（石蔵） database system including:
- Static code analysis
- Configuration security checks  
- Network security validation
- Input validation testing
- Authentication/authorization flaws
"""

import os
import sys
import subprocess
import json
import re
import argparse
from pathlib import Path
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum

class SeverityLevel(Enum):
    INFO = "info"
    LOW = "low" 
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class SecurityFinding:
    id: str
    title: str
    description: str
    severity: SeverityLevel
    file_path: str = ""
    line_number: int = 0
    recommendation: str = ""
    cwe_id: str = ""

class SecurityScanner:
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.findings: List[SecurityFinding] = []
        
    def add_finding(self, finding: SecurityFinding):
        """Add a security finding to the results"""
        self.findings.append(finding)
        
    def scan_all(self) -> List[SecurityFinding]:
        """Run all security scans"""
        print("🔍 Starting comprehensive security scan...")
        
        self.scan_source_code()
        self.scan_build_configuration()
        self.scan_network_security()
        self.scan_cryptography_usage()
        self.scan_input_validation()
        self.scan_authentication_flaws()
        self.scan_file_permissions()
        self.scan_dependencies()
        
        return self.findings
    
    def scan_source_code(self):
        """Scan source code for security vulnerabilities"""
        print("📁 Scanning source code for vulnerabilities...")
        
        source_dirs = ["src", "include"]
        file_extensions = [".cpp", ".hpp", ".h", ".c"]
        
        for src_dir in source_dirs:
            src_path = self.project_root / src_dir
            if not src_path.exists():
                continue
                
            for file_path in src_path.rglob("*"):
                if file_path.suffix in file_extensions:
                    self._scan_file_for_vulnerabilities(file_path)
    
    def _scan_file_for_vulnerabilities(self, file_path: Path):
        """Scan individual file for security issues"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.splitlines()
                
            # Check for dangerous functions
            dangerous_functions = [
                (r'\bstrcpy\s*\(', "Use of dangerous strcpy function", "CWE-120"),
                (r'\bstrcat\s*\(', "Use of dangerous strcat function", "CWE-120"), 
                (r'\bsprintf\s*\(', "Use of dangerous sprintf function", "CWE-120"),
                (r'\bgets\s*\(', "Use of dangerous gets function", "CWE-120"),
                (r'\bsystem\s*\(', "Use of system() function", "CWE-78"),
                (r'\bexec[lv]p?\s*\(', "Use of exec family functions", "CWE-78"),
                (r'\bpopen\s*\(', "Use of popen function", "CWE-78"),
            ]
            
            for line_num, line in enumerate(lines, 1):
                for pattern, desc, cwe in dangerous_functions:
                    if re.search(pattern, line, re.IGNORECASE):
                        self.add_finding(SecurityFinding(
                            id=f"VULN-{len(self.findings)+1:04d}",
                            title=f"Dangerous Function Usage",
                            description=f"{desc}: {line.strip()}",
                            severity=SeverityLevel.HIGH,
                            file_path=str(file_path.relative_to(self.project_root)),
                            line_number=line_num,
                            recommendation="Replace with safer alternatives (strncpy, snprintf, etc.)",
                            cwe_id=cwe
                        ))
            
            # Check for hardcoded secrets
            secret_patterns = [
                (r'password\s*[=:]\s*["\'][^"\']{8,}["\']', "Hardcoded password"),
                (r'secret\s*[=:]\s*["\'][^"\']{8,}["\']', "Hardcoded secret"),
                (r'api[_-]?key\s*[=:]\s*["\'][^"\']{8,}["\']', "Hardcoded API key"),
                (r'token\s*[=:]\s*["\'][^"\']{8,}["\']', "Hardcoded token"),
                (r'-----BEGIN [A-Z ]+PRIVATE KEY-----', "Private key in source"),
            ]
            
            for line_num, line in enumerate(lines, 1):
                for pattern, desc in secret_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        self.add_finding(SecurityFinding(
                            id=f"SECRET-{len(self.findings)+1:04d}",
                            title="Hardcoded Secrets",
                            description=f"{desc} found in source code",
                            severity=SeverityLevel.CRITICAL,
                            file_path=str(file_path.relative_to(self.project_root)),
                            line_number=line_num,
                            recommendation="Move secrets to environment variables or secure vault",
                            cwe_id="CWE-798"
                        ))
            
            # Check for SQL injection vulnerabilities
            sql_injection_patterns = [
                (r'query\s*[+=]\s*["\'][^"\']*\+', "String concatenation in query"),
                (r'execute\s*\([^)]*\+', "String concatenation in execute"),
            ]
            
            for line_num, line in enumerate(lines, 1):
                for pattern, desc in sql_injection_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        self.add_finding(SecurityFinding(
                            id=f"SQLI-{len(self.findings)+1:04d}",
                            title="Potential SQL Injection",
                            description=f"{desc}: {line.strip()}",
                            severity=SeverityLevel.HIGH,
                            file_path=str(file_path.relative_to(self.project_root)),
                            line_number=line_num,
                            recommendation="Use parameterized queries or prepared statements",
                            cwe_id="CWE-89"
                        ))
                        
        except Exception as e:
            print(f"⚠️  Error scanning {file_path}: {e}")
    
    def scan_build_configuration(self):
        """Scan build configuration for security issues"""
        print("🔧 Scanning build configuration...")
        
        cmake_files = list(self.project_root.rglob("CMakeLists.txt"))
        cmake_files.extend(list(self.project_root.rglob("*.cmake")))
        
        for cmake_file in cmake_files:
            try:
                with open(cmake_file, 'r') as f:
                    content = f.read()
                
                # Check for security compilation flags
                security_flags = {
                    'stack-protector': r'-fstack-protector',
                    'fortify-source': r'-D_FORTIFY_SOURCE=2',
                    'pie': r'-fPIE',
                    'relro': r'-Wl,-z,relro',
                    'now': r'-Wl,-z,now',
                    'nx': r'-Wl,-z,noexecstack'
                }
                
                missing_flags = []
                for flag_name, pattern in security_flags.items():
                    if not re.search(pattern, content, re.IGNORECASE):
                        missing_flags.append(flag_name)
                
                if missing_flags:
                    self.add_finding(SecurityFinding(
                        id=f"BUILD-{len(self.findings)+1:04d}",
                        title="Missing Security Compilation Flags",
                        description=f"Missing security flags: {', '.join(missing_flags)}",
                        severity=SeverityLevel.MEDIUM,
                        file_path=str(cmake_file.relative_to(self.project_root)),
                        recommendation="Add recommended security compilation flags",
                        cwe_id="CWE-693"
                    ))
                    
                # Check for debug flags in release builds
                if re.search(r'CMAKE_BUILD_TYPE.*Debug', content) and \
                   re.search(r'-DNDEBUG', content):
                    self.add_finding(SecurityFinding(
                        id=f"BUILD-{len(self.findings)+1:04d}",
                        title="Mixed Debug/Release Configuration",
                        description="Debug and release flags mixed in build configuration",
                        severity=SeverityLevel.LOW,
                        file_path=str(cmake_file.relative_to(self.project_root)),
                        recommendation="Ensure consistent build configuration",
                        cwe_id="CWE-489"
                    ))
                    
            except Exception as e:
                print(f"⚠️  Error scanning {cmake_file}: {e}")
    
    def scan_network_security(self):
        """Scan network configuration for security issues"""
        print("🌐 Scanning network security configuration...")
        
        # Check TLS configuration
        tls_files = list(self.project_root.rglob("*tls*"))
        tls_files.extend(list(self.project_root.rglob("*ssl*")))
        
        for tls_file in tls_files:
            if tls_file.suffix in ['.cpp', '.hpp', '.h']:
                try:
                    with open(tls_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    # Check for weak TLS versions
                    if re.search(r'TLS1_VERSION|SSL[23]_VERSION', content):
                        self.add_finding(SecurityFinding(
                            id=f"TLS-{len(self.findings)+1:04d}",
                            title="Weak TLS Version",
                            description="Support for TLS 1.0/1.1 or SSL detected",
                            severity=SeverityLevel.HIGH,
                            file_path=str(tls_file.relative_to(self.project_root)),
                            recommendation="Use TLS 1.2 or higher only",
                            cwe_id="CWE-327"
                        ))
                    
                    # Check for weak ciphers
                    weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'SHA1']
                    for cipher in weak_ciphers:
                        if re.search(rf'\b{cipher}\b', content, re.IGNORECASE):
                            self.add_finding(SecurityFinding(
                                id=f"CIPHER-{len(self.findings)+1:04d}",
                                title="Weak Cipher Usage",
                                description=f"Weak cipher {cipher} detected in configuration",
                                severity=SeverityLevel.HIGH,
                                file_path=str(tls_file.relative_to(self.project_root)),
                                recommendation="Use strong ciphers (AES-GCM, ChaCha20-Poly1305)",
                                cwe_id="CWE-327"
                            ))
                            
                except Exception as e:
                    print(f"⚠️  Error scanning {tls_file}: {e}")
    
    def scan_cryptography_usage(self):
        """Scan cryptographic implementation for issues"""
        print("🔐 Scanning cryptography usage...")
        
        crypto_patterns = [
            (r'\bMD5\b', "MD5 usage detected", SeverityLevel.HIGH, "Use SHA-256 or better"),
            (r'\bSHA1\b', "SHA-1 usage detected", SeverityLevel.MEDIUM, "Use SHA-256 or better"),
            (r'\bRAND\(\)', "Weak random number generator", SeverityLevel.HIGH, "Use cryptographically secure RNG"),
            (r'\bsrand\s*\(', "Weak random seed", SeverityLevel.MEDIUM, "Use secure random seeding"),
            (r'static.*iv\b', "Static IV usage", SeverityLevel.CRITICAL, "Generate random IV for each encryption"),
            (r'static.*salt\b', "Static salt usage", SeverityLevel.HIGH, "Generate random salt for each hash"),
        ]
        
        source_files = list(self.project_root.rglob("*.cpp"))
        source_files.extend(list(self.project_root.rglob("*.hpp")))
        
        for file_path in source_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.splitlines()
                
                for line_num, line in enumerate(lines, 1):
                    for pattern, desc, severity, rec in crypto_patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            self.add_finding(SecurityFinding(
                                id=f"CRYPTO-{len(self.findings)+1:04d}",
                                title="Cryptographic Weakness",
                                description=f"{desc}: {line.strip()}",
                                severity=severity,
                                file_path=str(file_path.relative_to(self.project_root)),
                                line_number=line_num,
                                recommendation=rec,
                                cwe_id="CWE-327"
                            ))
                            
            except Exception as e:
                print(f"⚠️  Error scanning {file_path}: {e}")
    
    def scan_input_validation(self):
        """Scan for input validation issues"""
        print("✅ Scanning input validation...")
        
        validation_patterns = [
            (r'atoi\s*\(', "Unsafe integer conversion", "Use strtol with error checking"),
            (r'atof\s*\(', "Unsafe float conversion", "Use strtod with error checking"),
            (r'scanf\s*\(', "Unsafe input function", "Use fgets with length checking"),
            (r'fscanf\s*\(', "Unsafe input function", "Use fgets with length checking"),
        ]
        
        source_files = list(self.project_root.rglob("*.cpp"))
        source_files.extend(list(self.project_root.rglob("*.c")))
        
        for file_path in source_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.splitlines()
                
                for line_num, line in enumerate(lines, 1):
                    for pattern, desc, rec in validation_patterns:
                        if re.search(pattern, line):
                            self.add_finding(SecurityFinding(
                                id=f"INPUT-{len(self.findings)+1:04d}",
                                title="Input Validation Issue",
                                description=f"{desc}: {line.strip()}",
                                severity=SeverityLevel.MEDIUM,
                                file_path=str(file_path.relative_to(self.project_root)),
                                line_number=line_num,
                                recommendation=rec,
                                cwe_id="CWE-20"
                            ))
                            
            except Exception as e:
                print(f"⚠️  Error scanning {file_path}: {e}")
    
    def scan_authentication_flaws(self):
        """Scan for authentication and authorization flaws"""
        print("🔑 Scanning authentication mechanisms...")
        
        auth_files = list(self.project_root.rglob("*auth*"))
        auth_files.extend(list(self.project_root.rglob("*security*")))
        
        for file_path in auth_files:
            if file_path.suffix in ['.cpp', '.hpp', '.h']:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        lines = content.splitlines()
                    
                    # Check for weak password policies
                    if re.search(r'password.*length.*[<].*8', content, re.IGNORECASE):
                        self.add_finding(SecurityFinding(
                            id=f"AUTH-{len(self.findings)+1:04d}",
                            title="Weak Password Policy",
                            description="Password minimum length less than 8 characters",
                            severity=SeverityLevel.MEDIUM,
                            file_path=str(file_path.relative_to(self.project_root)),
                            recommendation="Require minimum 8-character passwords with complexity",
                            cwe_id="CWE-521"
                        ))
                    
                    # Check for session management issues
                    session_patterns = [
                        (r'session.*timeout.*>\s*3600', "Long session timeout", "Reduce session timeout"),
                        (r'session.*id.*=.*\d+', "Predictable session ID", "Use secure random session IDs"),
                    ]
                    
                    for line_num, line in enumerate(lines, 1):
                        for pattern, desc, rec in session_patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                self.add_finding(SecurityFinding(
                                    id=f"SESSION-{len(self.findings)+1:04d}",
                                    title="Session Management Issue",
                                    description=f"{desc}: {line.strip()}",
                                    severity=SeverityLevel.MEDIUM,
                                    file_path=str(file_path.relative_to(self.project_root)),
                                    line_number=line_num,
                                    recommendation=rec,
                                    cwe_id="CWE-613"
                                ))
                                
                except Exception as e:
                    print(f"⚠️  Error scanning {file_path}: {e}")
    
    def scan_file_permissions(self):
        """Scan for file permission issues"""
        print("📂 Scanning file permissions...")
        
        sensitive_files = [
            "*.key", "*.pem", "*.crt", "*.p12", "*.jks",
            "config", "*.conf", "*.cfg", "*.ini", "*.env"
        ]
        
        for pattern in sensitive_files:
            for file_path in self.project_root.rglob(pattern):
                try:
                    stat_info = file_path.stat()
                    mode = oct(stat_info.st_mode)[-3:]  # Last 3 digits are permissions
                    
                    # Check for overly permissive files
                    if mode in ['777', '776', '775', '774', '666', '664']:
                        self.add_finding(SecurityFinding(
                            id=f"PERM-{len(self.findings)+1:04d}",
                            title="Insecure File Permissions",
                            description=f"File has overly permissive permissions ({mode})",
                            severity=SeverityLevel.MEDIUM,
                            file_path=str(file_path.relative_to(self.project_root)),
                            recommendation="Restrict file permissions (644 for files, 755 for directories)",
                            cwe_id="CWE-732"
                        ))
                        
                except Exception as e:
                    print(f"⚠️  Error checking permissions for {file_path}: {e}")
    
    def scan_dependencies(self):
        """Scan dependencies for known vulnerabilities"""
        print("📦 Scanning dependencies...")
        
        # Check for CMake find_package calls
        cmake_files = list(self.project_root.rglob("CMakeLists.txt"))
        
        # Known vulnerable packages (this would be updated from CVE databases)
        vulnerable_packages = {
            'openssl': {'versions': ['< 1.1.1'], 'cve': 'CVE-2019-1551'},
            'libcurl': {'versions': ['< 7.68.0'], 'cve': 'CVE-2020-8177'},
        }
        
        for cmake_file in cmake_files:
            try:
                with open(cmake_file, 'r') as f:
                    content = f.read()
                
                # Extract package dependencies
                find_package_pattern = r'find_package\s*\(\s*([^\s)]+)'
                packages = re.findall(find_package_pattern, content, re.IGNORECASE)
                
                for package in packages:
                    package_lower = package.lower()
                    if package_lower in vulnerable_packages:
                        vuln_info = vulnerable_packages[package_lower]
                        self.add_finding(SecurityFinding(
                            id=f"DEP-{len(self.findings)+1:04d}",
                            title="Potentially Vulnerable Dependency",
                            description=f"Package {package} may be vulnerable ({vuln_info['cve']})",
                            severity=SeverityLevel.MEDIUM,
                            file_path=str(cmake_file.relative_to(self.project_root)),
                            recommendation=f"Update {package} to latest version",
                            cwe_id="CWE-1104"
                        ))
                        
            except Exception as e:
                print(f"⚠️  Error scanning dependencies in {cmake_file}: {e}")
    
    def generate_report(self, output_format: str = "json") -> str:
        """Generate security report"""
        if output_format.lower() == "json":
            return self._generate_json_report()
        elif output_format.lower() == "html":
            return self._generate_html_report()
        else:
            return self._generate_text_report()
    
    def _generate_json_report(self) -> str:
        """Generate JSON security report"""
        report = {
            "scan_timestamp": "2025-08-27T02:50:00Z",
            "project_root": str(self.project_root),
            "summary": {
                "total_findings": len(self.findings),
                "critical": len([f for f in self.findings if f.severity == SeverityLevel.CRITICAL]),
                "high": len([f for f in self.findings if f.severity == SeverityLevel.HIGH]),
                "medium": len([f for f in self.findings if f.severity == SeverityLevel.MEDIUM]),
                "low": len([f for f in self.findings if f.severity == SeverityLevel.LOW]),
                "info": len([f for f in self.findings if f.severity == SeverityLevel.INFO])
            },
            "findings": []
        }
        
        for finding in self.findings:
            report["findings"].append({
                "id": finding.id,
                "title": finding.title,
                "description": finding.description,
                "severity": finding.severity.value,
                "file_path": finding.file_path,
                "line_number": finding.line_number,
                "recommendation": finding.recommendation,
                "cwe_id": finding.cwe_id
            })
        
        return json.dumps(report, indent=2)
    
    def _generate_text_report(self) -> str:
        """Generate text security report"""
        report = []
        report.append("=" * 60)
        report.append("IshikuraDB（石蔵） Security Scan Report")
        report.append("=" * 60)
        report.append(f"Project Root: {self.project_root}")
        report.append(f"Total Findings: {len(self.findings)}")
        report.append("")
        
        # Summary by severity
        severity_counts = {}
        for severity in SeverityLevel:
            count = len([f for f in self.findings if f.severity == severity])
            if count > 0:
                severity_counts[severity.value.upper()] = count
        
        if severity_counts:
            report.append("Summary by Severity:")
            for severity, count in severity_counts.items():
                report.append(f"  {severity}: {count}")
            report.append("")
        
        # Detailed findings
        if self.findings:
            report.append("Detailed Findings:")
            report.append("-" * 40)
            
            for i, finding in enumerate(self.findings, 1):
                report.append(f"{i}. [{finding.severity.value.upper()}] {finding.title}")
                report.append(f"   ID: {finding.id}")
                report.append(f"   Description: {finding.description}")
                if finding.file_path:
                    location = finding.file_path
                    if finding.line_number:
                        location += f":{finding.line_number}"
                    report.append(f"   Location: {location}")
                if finding.recommendation:
                    report.append(f"   Recommendation: {finding.recommendation}")
                if finding.cwe_id:
                    report.append(f"   CWE: {finding.cwe_id}")
                report.append("")
        else:
            report.append("✅ No security issues found!")
        
        return "\n".join(report)
    
    def _generate_html_report(self) -> str:
        """Generate HTML security report"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>IshikuraDB（石蔵） Security Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .summary {{ background: #ecf0f1; padding: 15px; margin: 20px 0; border-radius: 5px; }}
        .finding {{ margin: 20px 0; padding: 15px; border-left: 4px solid #ccc; }}
        .critical {{ border-left-color: #e74c3c; }}
        .high {{ border-left-color: #f39c12; }}
        .medium {{ border-left-color: #f1c40f; }}
        .low {{ border-left-color: #27ae60; }}
        .info {{ border-left-color: #3498db; }}
        .severity {{ font-weight: bold; text-transform: uppercase; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>IshikuraDB（石蔵） Security Scan Report</h1>
        <p>Project: {self.project_root}</p>
        <p>Scan Date: 2025-08-27</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <p>Total Findings: <strong>{len(self.findings)}</strong></p>
        <ul>
"""
        
        for severity in SeverityLevel:
            count = len([f for f in self.findings if f.severity == severity])
            if count > 0:
                html += f"<li>{severity.value.title()}: {count}</li>\n"
        
        html += """
        </ul>
    </div>
    
    <div class="findings">
        <h2>Detailed Findings</h2>
"""
        
        for finding in self.findings:
            severity_class = finding.severity.value
            html += f"""
        <div class="finding {severity_class}">
            <h3>[<span class="severity {severity_class}">{finding.severity.value}</span>] {finding.title}</h3>
            <p><strong>ID:</strong> {finding.id}</p>
            <p><strong>Description:</strong> {finding.description}</p>
"""
            if finding.file_path:
                location = finding.file_path
                if finding.line_number:
                    location += f":{finding.line_number}"
                html += f"<p><strong>Location:</strong> {location}</p>\n"
            
            if finding.recommendation:
                html += f"<p><strong>Recommendation:</strong> {finding.recommendation}</p>\n"
            
            if finding.cwe_id:
                html += f"<p><strong>CWE:</strong> {finding.cwe_id}</p>\n"
            
            html += "</div>\n"
        
        html += """
    </div>
</body>
</html>
"""
        return html

def main():
    parser = argparse.ArgumentParser(description="IshikuraDB（石蔵） Security Scanner")
    parser.add_argument("--project-root", default=".", 
                       help="Project root directory (default: current directory)")
    parser.add_argument("--output", choices=["text", "json", "html"], default="text",
                       help="Output format (default: text)")
    parser.add_argument("--output-file", help="Output file path")
    parser.add_argument("--severity-filter", choices=["info", "low", "medium", "high", "critical"],
                       help="Filter findings by minimum severity")
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = SecurityScanner(args.project_root)
    
    # Run security scan
    findings = scanner.scan_all()
    
    # Filter by severity if requested
    if args.severity_filter:
        severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        min_level = severity_order[args.severity_filter]
        findings = [f for f in findings if severity_order[f.severity.value] >= min_level]
        scanner.findings = findings
    
    # Generate report
    report = scanner.generate_report(args.output)
    
    # Output report
    if args.output_file:
        with open(args.output_file, 'w') as f:
            f.write(report)
        print(f"📄 Report saved to: {args.output_file}")
    else:
        print(report)
    
    # Exit with appropriate code
    critical_count = len([f for f in findings if f.severity == SeverityLevel.CRITICAL])
    high_count = len([f for f in findings if f.severity == SeverityLevel.HIGH])
    
    if critical_count > 0:
        print(f"\n❌ {critical_count} critical security issues found!")
        sys.exit(2)
    elif high_count > 0:
        print(f"\n⚠️  {high_count} high-severity security issues found!")
        sys.exit(1)
    else:
        print(f"\n✅ Security scan completed. {len(findings)} total findings.")
        sys.exit(0)

if __name__ == "__main__":
    main()