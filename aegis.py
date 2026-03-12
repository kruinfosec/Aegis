#!/usr/bin/env python3
"""
Aegis — Smart Contract Vulnerability Scanner (CLI)
Command-line interface for the Aegis scanner engine.
"""

import argparse
import sys
import json
import os
from scanner import engine

# Fix for Windows console emoji encoding
if sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        pass

def main():
    parser = argparse.ArgumentParser(
        description="Aegis Smart Contract Vulnerability Scanner",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        "target",
        help="Path to the Solidity (.sol) file or directory to scan"
    )
    
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)"
    )

    args = parser.parse_args()

    target_path = os.path.abspath(args.target)

    if not os.path.exists(target_path):
        print(f"Error: Target path '{target_path}' does not exist.", file=sys.stderr)
        sys.exit(1)

    files_to_scan = []
    if os.path.isfile(target_path):
        if not target_path.endswith('.sol'):
            print(f"Error: File '{target_path}' is not a .sol file.", file=sys.stderr)
            sys.exit(1)
        files_to_scan.append(target_path)
    elif os.path.isdir(target_path):
        for root, _, files in os.walk(target_path):
            for file in files:
                if file.endswith('.sol'):
                    files_to_scan.append(os.path.join(root, file))
        
        if not files_to_scan:
            print(f"No .sol files found in directory '{target_path}'.", file=sys.stderr)
            sys.exit(0)

    # Scan all files
    results = []
    for filepath in files_to_scan:
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                source_code = f.read()
            
            filename = os.path.basename(filepath)
            scan_result = engine.scan(source_code, filename=filename)
            results.append(scan_result)
            
        except Exception as e:
            results.append({
                "success": False,
                "error": str(e),
                "filename": os.path.basename(filepath)
            })

    # Print output
    if args.format == "json":
        print(json.dumps(results, indent=2))
    else:
        for result in results:
            print(f"\n{'='*60}")
            print(f"📄 Report for: {result.get('filename', 'Unknown')}")
            print(f"{'='*60}")
            
            if not result.get("success"):
                print(f"[!] Scan Error: {result.get('error')}")
                continue
                
            print(f"Risk Level : {result.get('risk_level')} (Score: {result.get('risk_score')})")
            print(f"Solidity   : {result.get('pragma_version') or 'Unknown'}")
            print(f"Issues     : {result.get('total_issues')}")
            print("-" * 60)
            
            if result.get("total_issues") == 0:
                print("✅ No vulnerabilities detected. Contract appears safe.")
            else:
                for i, finding in enumerate(result.get("findings", [])):
                    print(f"\n[{i+1}] {finding['vulnerability']} ({finding['severity']})")
                    print(f"    Line : {finding['line']}")
                    print(f"    Desc : {finding['description']}")
                    print(f"    Fix  : {finding['fix']}")
                    
        print(f"\n{'='*60}\n")

if __name__ == "__main__":
    main()
