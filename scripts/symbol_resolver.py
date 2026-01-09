#!/usr/bin/env python3
import subprocess
import os
import argparse
import sys

def resolve_trace(trace_file, symbol_root, use_same_paths: bool):
    if not os.path.exists(trace_file):
        print(f"Error: Trace file not found at {trace_file}")
        sys.exit(1)

    with open(trace_file, 'r') as f:
        lines = f.readlines()

    try:
        build_id = lines[1].strip().split(": ")[1]
    except (IndexError, ValueError):
        print("Error: Trace file must contain 'BUILD_ID: <id>'")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f" RESOLVING CRASH: {build_id}")
    print(f"{'='*60}\n")

    for line in lines[2:]:
        parts = line.split()
        if len(parts) < 3:
            continue
        
        offset = parts[1]
        original_path = parts[2]
        
        # Look for the debug file (assuming .debug extension in archive)
        pathExists: bool = False
        if use_same_paths:
            binary_name = os.path.basename(original_path)
            symbol_path = original_path
            pathExists = os.path.exists(symbol_path)
        else:
            binary_name = os.path.basename(original_path) + ".debug"
            symbol_path = os.path.join(symbol_root, build_id, binary_name)
            pathExists = os.path.exists(symbol_path)
            if not pathExists:
                #print(f'Symbol does not exist in {symbol_path}. Trying with literal path: {original_path}')
                binary_name = os.path.basename(original_path)
                symbol_path = original_path
                pathExists = os.path.join(symbol_path)
        
        if pathExists:
            try:
                # -e: debug file, -f: function names, -C: demangle, -p: pretty print
                result = subprocess.check_output(
                    ["addr2line", "-e", symbol_path, "-f", "-C", "-p", offset],
                    text=True, stderr=subprocess.STDOUT
                )
                print(f"{offset.ljust(18)} | {result.strip()}")
            except subprocess.CalledProcessError:
                print(f"{offset.ljust(18)} | [addr2line failed for {binary_name}]")
        else:
            print(f"{offset.ljust(18)} | [Symbols Missing: {symbol_path}]")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Trace Resolver: Converts hex offsets to source code lines."
    )
    parser.add_argument(
        "trace", 
        help="Path to the .trace file received from the user."
    )
    parser.add_argument(
        "--symbols", 
        default="symbol_archive",
        help="Root directory of your symbol archive (default: symbol_archive)"
    )
    parser.add_argument("--use_same_paths", default=False, help="Direcly uses the symbol path on each frame as base for addr2line. Use on debug builds or on reports generated on the same machine as this script")

    args = parser.parse_args()
    resolve_trace(args.trace, args.symbols, args.use_same_paths)