#!/usr/bin/env python3
"""
PHIDS Project Cleanup Script
Removes unnecessary files, redundant code, and optimizes project structure
"""

import os
import shutil
import sys
from pathlib import Path
import argparse

class PHIDSProjectCleanup:
    """Automated cleanup for PHIDS project"""
    
    def __init__(self, dry_run=True):
        self.dry_run = dry_run
        self.project_root = Path(__file__).parent
        self.removed_files = []
        self.removed_dirs = []
        self.cleaned_dependencies = []
        
    def log_action(self, action, path):
        """Log cleanup actions"""
        if self.dry_run:
            print(f"[DRY RUN] {action}: {path}")
        else:
            print(f"[CLEANUP] {action}: {path}")
    
    def remove_file(self, file_path):
        """Remove a file"""
        if file_path.exists():
            self.log_action("REMOVE FILE", file_path)
            if not self.dry_run:
                file_path.unlink()
                self.removed_files.append(str(file_path))
    
    def remove_directory(self, dir_path):
        """Remove a directory and its contents"""
        if dir_path.exists():
            self.log_action("REMOVE DIR", dir_path)
            if not self.dry_run:
                shutil.rmtree(dir_path)
                self.removed_dirs.append(str(dir_path))
    
    def cleanup_redundant_test_files(self):
        """Remove redundant and outdated test files"""
        print("\n🧹 Cleaning up redundant test files...")
        
        # Redundant test files to remove
        redundant_tests = [
            "test_broadcast_event_fix.py",
            "test_controls_button.py", 
            "test_controls_button_fix.py",
            "test_controls_functionality.py",
            "test_critical_fixes.py",
            "test_dashboard_fixes.py",
            "test_enhanced_dashboard.py",
            "test_manual_attacks.py",
            "test_real_time_monitoring.py",
            "test_ssh_status_classification.py",
            "test_ssh_status_fix.py"
        ]
        
        for test_file in redundant_tests:
            self.remove_file(self.project_root / test_file)
    
    def cleanup_debug_files(self):
        """Remove debug and diagnostic files"""
        print("\n🔍 Cleaning up debug files...")
        
        debug_files = [
            "check_logs.py",
            "debug_ssh_status.py", 
            "diagnose_phids_issues.py",
            "fix_all_critical_issues.py",
            "create_favicon.py"
        ]
        
        for debug_file in debug_files:
            self.remove_file(self.project_root / debug_file)
    
    def cleanup_cache_files(self):
        """Remove Python cache files and directories"""
        print("\n🗂️ Cleaning up cache files...")
        
        # Remove __pycache__ directories
        for pycache_dir in self.project_root.rglob("__pycache__"):
            self.remove_directory(pycache_dir)
        
        # Remove .pyc files
        for pyc_file in self.project_root.rglob("*.pyc"):
            self.remove_file(pyc_file)
    
    def cleanup_coverage_files(self):
        """Remove test coverage files"""
        print("\n📊 Cleaning up coverage files...")
        
        # Remove htmlcov directory
        self.remove_directory(self.project_root / "htmlcov")
        
        # Remove coverage files
        coverage_files = [".coverage", ".coverage.*"]
        for pattern in coverage_files:
            for file in self.project_root.glob(pattern):
                self.remove_file(file)
    
    def cleanup_log_files(self):
        """Clean up old log files (keep recent ones)"""
        print("\n📝 Cleaning up old log files...")
        
        logs_dir = self.project_root / "logs"
        if logs_dir.exists():
            # Remove old rotated log files
            for log_file in logs_dir.glob("*.log.*"):
                self.remove_file(log_file)
            
            # Remove old analysis reports
            for report_file in logs_dir.glob("analysis_report_*.json"):
                self.remove_file(report_file)
    
    def cleanup_redundant_documentation(self):
        """Remove redundant documentation files"""
        print("\n📚 Cleaning up redundant documentation...")
        
        # Keep only essential documentation
        redundant_docs = [
            "ISSUE_RESOLUTION_SUMMARY.md",
            "SSH_STATUS_CLASSIFICATION_FIXES.md",
            "STARTUP_GUIDE.md"
        ]
        
        for doc_file in redundant_docs:
            self.remove_file(self.project_root / doc_file)
    
    def optimize_requirements(self):
        """Optimize requirements.txt by removing unused dependencies"""
        print("\n📦 Optimizing requirements.txt...")
        
        requirements_file = self.project_root / "requirements.txt"
        if not requirements_file.exists():
            return
        
        # Dependencies that are actually used based on code analysis
        used_dependencies = {
            # Core networking and security
            "scapy>=2.5.0",
            "paramiko>=3.3.1", 
            "requests>=2.31.0",
            
            # Database
            "aiosqlite>=0.20.0",
            
            # Monitoring
            "psutil>=5.9.0",
            
            # Visualization (used in reporting)
            "matplotlib>=3.7.0",
            "jinja2>=3.1.0",
            
            # Web framework
            "fastapi>=0.104.0",
            "uvicorn[standard]>=0.24.0",
            "websockets>=12.0",
            
            # Threat intelligence
            "aiohttp>=3.8.0",
            
            # Testing (keep for development)
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0"
        }
        
        # Dependencies to remove (unused or redundant)
        unused_dependencies = [
            "numpy",  # Not used in current implementation
            "plotly",  # Not used, matplotlib is sufficient
            "weasyprint",  # PDF generation not implemented
            "flask",  # Using FastAPI instead
            "flask-cors",  # Using FastAPI instead
            "python-whois",  # Not used in current implementation
            "pytest-cov",  # Coverage not needed for production
            "black",  # Development tool, not runtime dependency
            "flake8"  # Development tool, not runtime dependency
        ]
        
        if not self.dry_run:
            # Read current requirements
            with open(requirements_file, 'r') as f:
                lines = f.readlines()
            
            # Filter out unused dependencies
            new_lines = []
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Check if this dependency should be kept
                    keep_line = False
                    for used_dep in used_dependencies:
                        if line.split('>=')[0].split('==')[0] in used_dep:
                            keep_line = True
                            break
                    
                    # Check if this dependency should be removed
                    remove_line = False
                    for unused_dep in unused_dependencies:
                        if unused_dep in line.lower():
                            remove_line = True
                            self.cleaned_dependencies.append(line)
                            break
                    
                    if keep_line and not remove_line:
                        new_lines.append(line + '\n')
                elif line.startswith('#'):
                    new_lines.append(line + '\n')
            
            # Write optimized requirements
            with open(requirements_file, 'w') as f:
                f.writelines(new_lines)
            
            self.log_action("OPTIMIZED", requirements_file)
        else:
            self.log_action("WOULD OPTIMIZE", requirements_file)
            for dep in unused_dependencies:
                self.log_action("WOULD REMOVE DEPENDENCY", dep)
    
    def cleanup_reports_directory(self):
        """Clean up old reports"""
        print("\n📋 Cleaning up old reports...")
        
        reports_dir = self.project_root / "reports"
        if reports_dir.exists():
            # Remove all files in reports directory (they can be regenerated)
            for report_file in reports_dir.iterdir():
                if report_file.is_file():
                    self.remove_file(report_file)
    
    def run_cleanup(self):
        """Run all cleanup operations"""
        print(f"🧹 PHIDS Project Cleanup {'(DRY RUN)' if self.dry_run else '(LIVE)'}")
        print("=" * 60)
        
        # Run cleanup operations
        self.cleanup_redundant_test_files()
        self.cleanup_debug_files()
        self.cleanup_cache_files()
        self.cleanup_coverage_files()
        self.cleanup_log_files()
        self.cleanup_redundant_documentation()
        self.cleanup_reports_directory()
        self.optimize_requirements()
        
        # Summary
        print("\n" + "=" * 60)
        print("📊 Cleanup Summary")
        print("=" * 60)
        print(f"Files removed: {len(self.removed_files)}")
        print(f"Directories removed: {len(self.removed_dirs)}")
        print(f"Dependencies cleaned: {len(self.cleaned_dependencies)}")
        
        if self.removed_files:
            print("\n📄 Removed files:")
            for file in self.removed_files:
                print(f"  - {file}")
        
        if self.removed_dirs:
            print("\n📁 Removed directories:")
            for dir in self.removed_dirs:
                print(f"  - {dir}")
        
        if self.cleaned_dependencies:
            print("\n📦 Removed dependencies:")
            for dep in self.cleaned_dependencies:
                print(f"  - {dep}")
        
        if self.dry_run:
            print("\n💡 This was a dry run. Use --execute to perform actual cleanup.")
        else:
            print("\n✅ Cleanup completed successfully!")
            print("\n🔄 Next steps:")
            print("  1. Run: pip install -r requirements.txt")
            print("  2. Test the system: python main.py --debug")
            print("  3. Run tests: python -m pytest test_phids.py test_dashboard.py test_main.py")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="PHIDS Project Cleanup Tool")
    parser.add_argument("--execute", action="store_true", 
                       help="Execute cleanup (default is dry run)")
    parser.add_argument("--keep-tests", action="store_true",
                       help="Keep all test files")
    parser.add_argument("--keep-docs", action="store_true", 
                       help="Keep all documentation files")
    
    args = parser.parse_args()
    
    # Confirm if executing
    if args.execute:
        response = input("⚠️  This will permanently delete files. Continue? (y/N): ")
        if response.lower() != 'y':
            print("Cleanup cancelled.")
            return
    
    # Run cleanup
    cleanup = PHIDSProjectCleanup(dry_run=not args.execute)
    cleanup.run_cleanup()

if __name__ == "__main__":
    main()
