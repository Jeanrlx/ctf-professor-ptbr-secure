#!/usr/bin/env python3
"""
Install Setup - CTF Professor
==============================
Automates environment verification, Docker build, and dependency setup.
Used by the /install workflow.
"""

import os
import sys
import subprocess
import shutil
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger("install_setup")

class InstallSetup:
    def __init__(self, project_root: str = "."):
        self.project_root = Path(project_root).resolve()
        self.agent_dir = self.project_root / ".agent"
        self.sandbox_dir = self.agent_dir / "sandbox"
        self.image_name = "cyber-ctf-kali"
        self.required_python_libs = ["mcp", "fastmcp", "pwntools", "requests"]

    def check_core_tools(self):
        """Check for core system requirements."""
        tools = {
            "docker": "Docker is required for the sandbox environment.",
            "python": "Python 3.8+ is required for the CTF Professor scripts.",
            "git": "Git is required for version control."
        }
        
        status = {}
        for tool, reason in tools.items():
            path = shutil.which(tool)
            status[tool] = {
                "installed": path is not None,
                "path": path if path else "Not Found",
                "reason": reason
            }
        return status

    def check_docker_image(self):
        """Check if the Docker image already exists."""
        try:
            result = subprocess.run(
                ["docker", "images", "-q", self.image_name],
                capture_output=True, text=True, check=True
            )
            return len(result.stdout.strip()) > 0
        except subprocess.CalledProcessError:
            return False

    def build_docker_image(self, force: bool = False):
        """Build the Docker sandbox image."""
        if self.check_docker_image() and not force:
            logger.info(f"Docker image '{self.image_name}' already exists. Use --force to rebuild.")
            return True

        dockerfile = self.sandbox_dir / "Dockerfile"
        if not dockerfile.exists():
            logger.error(f"Dockerfile not found at {dockerfile}")
            return False

        logger.info(f"Building Docker image '{self.image_name}'...")
        try:
            subprocess.run(
                ["docker", "build", "-t", self.image_name, str(self.sandbox_dir)],
                check=True
            )
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to build Docker image: {e}")
            return False

    def check_python_libs(self):
        """Check for required Python libraries."""
        import importlib
        missing = []
        for lib in self.required_python_libs:
            try:
                importlib.import_module(lib)
            except ImportError:
                missing.append(lib)
        return missing

    def install_python_libs(self, libs: list):
        """Install missing Python libraries."""
        if not libs:
            return True
        
        logger.info(f"Installing missing libraries: {', '.join(libs)}...")
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install"] + libs,
                check=True
            )
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install libraries: {e}")
            return False

    def setup_local_tools(self):
        """Verify and suggest local tools for CTF on the host."""
        logger.info("\n--- Local Toolchain Verification (Host) ---")
        logger.info("Checking for recommended lightweight tools for CTF analysis...")
        
        env_path = self.project_root / ".env"
        env_content = []
        if env_path.exists():
            with open(env_path, 'r') as f:
                env_content = f.readlines()
        
        new_env_values = {}
        
        # 1. Notepad++
        npp_path = shutil.which("notepad++") or os.path.exists("C:\\Program Files\\Notepad++\\notepad++.exe")
        if npp_path:
            logger.info("✅ Notepad++: Found.")
            new_env_values["HAS_NOTEPADPP"] = "true"
        else:
            logger.warning("❌ Notepad++: Not found. (Recommended for large files, Hex/Base64/JSON plugins)")
            if sys.platform == "win32":
                logger.info("   -> Install via winget: winget install Notepad++.Notepad++")
            
        # 2. Hex Editor
        hex_editor = shutil.which("imhex") or shutil.which("hxd") or os.path.exists("C:\\Program Files\\ImHex\\imhex.exe")
        if hex_editor:
            logger.info("✅ Hex Editor (ImHex/HxD): Found.")
            new_env_values["HAS_HEXEDITOR"] = "true"
        else:
            logger.warning("❌ Dedicated Hex Editor: Not found. (Recommended for Pwn/Forensics)")
            if sys.platform == "win32":
                logger.info("   -> Install ImHex: winget install WerWolv.ImHex")
                
        # 3. CyberChef
        has_cc = input("Do you have CyberChef downloaded locally? (y/n): ").strip().lower() == 'y'
        if has_cc:
             new_env_values["HAS_CYBERCHEF"] = "true"
             logger.info("✅ CyberChef: Confirmed.")
        else:
             logger.info("💡 Tip: Download CyberChef HTML locally to avoid uploading sensitive data to the web:")
             logger.info("   -> https://github.com/gchq/CyberChef/releases")

        # Update .env
        with open(env_path, 'w') as f:
            for line in env_content:
                if '=' in line:
                    k = line.split('=')[0]
                    if k not in new_env_values:
                        f.write(line)
            for k, v in new_env_values.items():
                f.write(f"{k}={v}\n")
                
        # Gemini Editor Tip
        logger.info("\n🛠️  Gemini CLI Editor Tip:")
        logger.info("To make Notepad++ your default editor for Gemini CLI, set the EDITOR environment variable:")
        if sys.platform == "win32":
            logger.info('   [Environment]::SetEnvironmentVariable("EDITOR", "C:\\Program Files\\Notepad++\\notepad++.exe", "User")')
        else:
            logger.info('   export EDITOR="notepad++"')

    @staticmethod
    def _sanitize_env_value(value: str) -> str:
        """
        Strip characters that could break .env parsing or enable injection.
        Newlines and null bytes are the most dangerous: a value containing '\n'
        would let an attacker write arbitrary additional keys into the file.
        """
        # Remove null bytes and newline characters entirely
        sanitized = value.replace('\x00', '').replace('\n', '').replace('\r', '')
        # Reject values that are suspiciously long (token/cookie max ~512 chars)
        if len(sanitized) > 512:
            raise ValueError(f"Value is too long ({len(sanitized)} chars). Max 512.")
        return sanitized

    def setup_ctf_platforms(self):
        """Guide the user through linking CTF platforms."""
        env_path = self.project_root / ".env"

        # Validate env_path stays inside project root (prevent path traversal)
        try:
            env_path.resolve().relative_to(self.project_root.resolve())
        except ValueError:
            logger.error("Attempted path traversal detected for .env path. Aborting.")
            return False

        logger.info("\n--- CTF Platform Connection (Optional) ---")
        logger.info("Linking your accounts enables automated challenge intake and flag submission.")

        platforms = {
            "1": ("CTFd", ["CTFD_URL", "CTFD_TOKEN"]),
            "2": ("HackTheBox", ["HTB_TOKEN"]),
            "3": ("TryHackMe", ["THM_SESSION_SID"])
        }

        logger.info("Available Platforms:\n1. CTFd\n2. HackTheBox\n3. TryHackMe\n4. Skip")
        choice = input("Select a platform to link (or 4 to skip): ")

        if choice in platforms:
            name, keys = platforms[choice]
            logger.info(f"\nConfiguring {name}...")

            if name == "CTFd":
                logger.info("Hint: Generate an Access Token in /settings > Access Tokens.")
            elif name == "HackTheBox":
                logger.info("Hint: Find your App Token in Profile Settings > App Tokens.")
            elif name == "TryHackMe":
                logger.info("Hint: Copy the 'connect.sid' cookie from your browser after logging in.")

            env_content = []
            if env_path.exists():
                with open(env_path, 'r') as f:
                    env_content = f.readlines()

            new_values = {}
            for key in keys:
                val = input(f"Enter {key}: ").strip()
                if val:
                    try:
                        new_values[key] = self._sanitize_env_value(val)
                    except ValueError as e:
                        logger.error(f"Invalid value for {key}: {e}")
                        return False

            # Write atomically: build full content first, then write once
            lines_out = []
            for line in env_content:
                if '=' in line:
                    k = line.split('=')[0].strip()
                    if k not in new_values:
                        lines_out.append(line)
            for k, v in new_values.items():
                lines_out.append(f"{k}={v}\n")

            with open(env_path, 'w') as f:
                f.writelines(lines_out)
            
            logger.info(f"✅ {name} configuration saved to .env")
            
            # Ensure .env is in .gitignore
            gitignore = self.project_root / ".gitignore"
            if gitignore.exists():
                with open(gitignore, 'a+') as f:
                    f.seek(0)
                    if ".env" not in f.read():
                        f.write("\n.env\n")
            
            return True
        return False

    def run_full_setup(self, force_rebuild: bool = False):
        """Execute the full setup sequence."""
        logger.info("Starting CTF Professor environment setup...")
        
        # 1. Core Tools
        tools = self.check_core_tools()
        for tool, info in tools.items():
            if not info["installed"]:
                logger.error(f"Missing core tool: {tool.upper()} - {info['reason']}")
                return False
            logger.info(f"✅ {tool.upper()} is installed at {info['path']}")

        # 2. Python Libs
        missing_libs = self.check_python_libs()
        if missing_libs:
            logger.warning(f"Missing Python libraries: {', '.join(missing_libs)}")
            if input("Would you like to install them now? (y/n): ").lower() == 'y':
                if not self.install_python_libs(missing_libs):
                    return False
        else:
            logger.info("✅ All required Python libraries are present.")

        # 3. Docker Image
        if not self.build_docker_image(force_rebuild):
            return False
        logger.info(f"✅ Docker image '{self.image_name}' is ready.")

        # 4. Local Tools
        self.setup_local_tools()

        # 5. CTF Platforms
        self.setup_ctf_platforms()

        logger.info("\n✨ Environment setup completed successfully! ✨")
        return True

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CTF Professor Setup Script")
    parser.add_argument("--force-rebuild", action="store_true", help="Force rebuild the Docker image")
    parser.add_argument("--check-only", action="store_true", help="Only check for dependencies, don't install")
    
    args = parser.parse_args()
    setup = InstallSetup()
    
    if args.check_only:
        tools = setup.check_core_tools()
        for tool, info in tools.items():
            print(f"{tool.upper()}: {'OK' if info['installed'] else 'MISSING'}")
        
        missing_libs = setup.check_python_libs()
        if missing_libs:
            print(f"Missing Libraries: {', '.join(missing_libs)}")
        else:
            print("Python Libs: OK")
            
        if setup.check_docker_image():
            print(f"Docker Image '{setup.image_name}': OK")
        else:
            print(f"Docker Image '{setup.image_name}': MISSING")
    else:
        success = setup.run_full_setup(args.force_rebuild)
        sys.exit(0 if success else 1)
