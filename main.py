#!/usr/bin/env python3
import os
import sys
import argparse
import time

# Ensure the project root is in the Python search path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from cbom import agent_a
from cbom import agent_b
from cbom import agent_c

def main():
    parser = argparse.ArgumentParser(
        description="Deterministic Cryptographic Blast Radius Analyzer (CBOM Generator)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "target_dir",
        help="Path to the targeted software repository to scan (Python/Go)"
    )
    parser.add_argument(
        "-o", "--output-dir",
        default="output",
        help="Directory to store all intermediate and final deliverables"
    )
    
    args = parser.parse_args()
    
    target_dir = os.path.abspath(args.target_dir)
    output_dir = os.path.abspath(args.output_dir)
    
    print("=" * 60)
    print("        Determinstic Cryptographic Blast Radius Analyzer        ")
    print("=" * 60)
    print(f"Target Directory: {target_dir}")
    print(f"Output Directory: {output_dir}")
    print("-" * 60)
    
    if not os.path.exists(target_dir):
        print(f"[-] Error: Target directory '{target_dir}' does not exist.")
        sys.exit(1)
        
    os.makedirs(output_dir, exist_ok=True)
    
    start_time = time.time()
    
    # -------------------------------------------------------------
    # Step 1: Execute Deterministic Module A (CBOM Extractor)
    # -------------------------------------------------------------
    print("[*] Step 1: Running Deterministic Module A (CBOM Extractor)...")
    cbom_path = os.path.join(output_dir, "cbom.json")
    try:
        agent_a.generate_cbom(target_dir, cbom_path)
        print(f"[+] Deterministic Module A completed successfully. CBOM saved to: {cbom_path}")
    except Exception as e:
        print(f"[-] Error in Deterministic Module A execution: {e}")
        sys.exit(1)
        
    print("-" * 60)
    
    # -------------------------------------------------------------
    # Step 2: Execute Deterministic Module B (AST CodeGraph Generator)
    # -------------------------------------------------------------
    print("[*] Step 2: Running Deterministic Module B (AST CodeGraph Generator)...")
    codegraph_path = os.path.join(output_dir, "codegraph.json")
    try:
        engine = agent_b.generate_codegraph(target_dir, codegraph_path)
        print(f"[+] Deterministic Module B completed successfully. Code Graph saved to: {codegraph_path}")
    except Exception as e:
        print(f"[-] Error in Deterministic Module B execution: {e}")
        sys.exit(1)
        
    print("-" * 60)
    
    # -------------------------------------------------------------
    # Step 3: Execute Deterministic Module C (Deterministic Junction Engine)
    # -------------------------------------------------------------
    print("[*] Step 3: Running Deterministic Module C (Deterministic Junction Engine)...")
    try:
        blast_radius = agent_c.analyze_cbom(
            cbom_path=cbom_path,
            engine=engine,
            output_dir=output_dir
        )
        print("[+] Deterministic Module C completed successfully.")
        
        # Print summary
        unreachable = blast_radius.get("Unreachable/Static Library Import", [])
        reachable_count = len(blast_radius) - 1 # exclude Unreachable key
        print(f"    - Reachable Vulnerable AST Nodes: {reachable_count}")
        print(f"    - Unreachable/Static Library Cryptographic Assets: {len(unreachable)}")
        
        zip_path = os.path.join(output_dir, "blast_radius.zip")
        print(f"[+] Deliverables packaged successfully into: {zip_path}")
    except Exception as e:
        print(f"[-] Error in Deterministic Module C execution: {e}")
        sys.exit(1)
        
    elapsed = time.time() - start_time
    print("=" * 60)
    print(f"[+] Cryptographic Blast Radius Analysis completed in {elapsed:.2f} seconds.")
    print("=" * 60)

if __name__ == "__main__":
    main()
