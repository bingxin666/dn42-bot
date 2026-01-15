#!/usr/bin/env python3
"""
Utility script to manually update the DN42 registry cache.

Usage:
    python3 update_registry.py [--force]

Options:
    --force    Force a fresh clone, removing existing registry
"""

import sys
import os
import argparse
import shutil

# Add the tools directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import registry


def main():
    parser = argparse.ArgumentParser(description='Update DN42 registry cache')
    parser.add_argument('--force', action='store_true',
                        help='Force fresh clone (removes existing registry)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Show verbose output')
    args = parser.parse_args()
    
    if args.force:
        if args.verbose:
            print(f"Removing existing registry at {registry.REGISTRY_PATH}...")
        if os.path.exists(registry.REGISTRY_PATH):
            shutil.rmtree(registry.REGISTRY_PATH)
            if args.verbose:
                print("Removed.")
    
    if args.verbose:
        print("Updating DN42 registry...")
        print(f"Source: {registry.REGISTRY_URL}")
        print(f"Destination: {registry.REGISTRY_PATH}")
        print()
    
    result = registry.ensure_registry_cloned()
    
    if result:
        if args.verbose:
            print("\n✓ Registry updated successfully!")
            
            # Show some stats
            asns = registry.list_all_asns()
            print(f"\nStatistics:")
            print(f"  Total ASNs: {len(asns)}")
            if asns:
                print(f"  ASN range: AS{min(asns)} - AS{max(asns)}")
            
            # Test a lookup
            if asns:
                test_asn = asns[0]
                mnt = registry.get_asn_field(test_asn, "mnt-by")
                as_name = registry.get_asn_field(test_asn, "as-name")
                print(f"\n  Sample ASN (AS{test_asn}):")
                print(f"    mnt-by: {mnt}")
                print(f"    as-name: {as_name}")
    else:
        print("✗ Failed to update registry!")
        print("Please check your network connection and try again.")
        sys.exit(1)


if __name__ == "__main__":
    main()
