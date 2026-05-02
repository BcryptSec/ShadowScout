from setuptools import setup, find_packages

setup(
    name="shadowscout",
    version="1.4.6",
    author="BcryptSec",
    description="Advanced Offensive Recon & Risk Scoring Engine",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/BcryptSec/ShadowScout",
    packages=find_packages(),
    install_requires=[
        "aiohttp",
        "beautifulsoup4",
        "colorama",
    ],
    entry_points={
        "console_scripts": [
            "shadowscout=shadowscout.shadowscout:main",
        ],
    },
    python_requires=">=3.7",
)
