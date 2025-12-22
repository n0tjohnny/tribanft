from setuptools import setup, find_packages
from setuptools.command.install import install
from pathlib import Path
import shutil
import os

class PostInstallCommand(install):
    """Post-installation for installation mode."""
    def run(self):
        install.run(self)

        # Determine config directory
        config_dir = Path.home() / '.local' / 'share' / 'tribanft'
        config_file = config_dir / 'config.conf'
        template_file = Path(__file__).parent / 'config.conf.template'

        # Create directory if it doesn't exist
        config_dir.mkdir(parents=True, exist_ok=True)

        # Copy template if config doesn't exist
        if not config_file.exists() and template_file.exists():
            print(f"Installing default config to {config_file}")
            shutil.copy(template_file, config_file)
            print(f"Config file created at {config_file}")
            print(f"Edit this file to customize your TribanFT installation")
        elif config_file.exists():
            print(f"Config file already exists at {config_file}")
            print(f"Not overwriting existing configuration")
        else:
            print(f"Warning: Template file not found at {template_file}")


setup(
    name="tribanft",
    version="2.2.0",
    packages=find_packages(),
    install_requires=[
        "pydantic",
    ],
    entry_points={
        'console_scripts': [
            'tribanft=bruteforce_detector.main:main',
        ],
    },
    cmdclass={
        'install': PostInstallCommand,
    },
    package_data={
        '': ['config.conf.template'],
    },
    include_package_data=True,
)
