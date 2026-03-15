"""
Centaur-Jarvis Directory Bruteforcer Module
============================================
Discovers hidden directories and files on web servers via brute-force
path enumeration using ffuf (primary) or gobuster (fallback).

Architecture:
- Consumes tasks from Redis queue `queue:dirbust`
- Manages wordlists with auto-download and caching
- Produces structured findings to `results:incoming`
- All status strings are UPPERCASE per TaskStatus schema
- Mandatory `data` field in all result dictionaries
"""

__version__ = "1.0.0"
__module_name__ = "dirbust"
