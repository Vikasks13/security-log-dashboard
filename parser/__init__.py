"""
Security Log Analytics Parser Package
"""

from .ssh_parser import parse_line, parse_file, SSHLogParser

__all__ = ["parse_line", "parse_file", "SSHLogParser"]
