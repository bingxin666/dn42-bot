"""
DN42 Registry local clone management and query module.
Handles cloning, updating, and querying the DN42 registry from local files.
"""
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional, Dict, List

# Registry configuration
REGISTRY_URL = "https://git.dn42.dev/dn42/registry.git"
REGISTRY_URL_FALLBACK = "https://github.com/dn42/registry.git"
CACHE_DIR = "./cache"
REGISTRY_PATH = os.path.join(CACHE_DIR, "registry")

# Lock for git operations
_git_lock = threading.Lock()


class RegistryError(Exception):
    """Exception raised for registry-related errors."""
    pass


def ensure_registry_cloned() -> bool:
    """
    Ensure the DN42 registry is cloned to the cache directory.
    If not present, clone it. If present, try to update it.
    
    Returns:
        bool: True if registry is available, False otherwise
    """
    with _git_lock:
        # Create cache directory if it doesn't exist
        os.makedirs(CACHE_DIR, exist_ok=True)
        
        if os.path.exists(REGISTRY_PATH) and os.path.isdir(os.path.join(REGISTRY_PATH, ".git")):
            # Repository already exists, try to update it
            try:
                result = subprocess.run(
                    ["git", "-C", REGISTRY_PATH, "pull", "--ff-only"],
                    capture_output=True,
                    timeout=30,
                    text=True
                )
                if result.returncode == 0:
                    return True
                else:
                    print(f"Failed to update registry: {result.stderr}")
                    # Continue to use existing repository even if update fails
                    return True
            except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
                print(f"Error updating registry: {e}")
                # Continue to use existing repository
                return True
        else:
            # Repository doesn't exist, clone it
            try:
                # Remove any existing files in the path
                if os.path.exists(REGISTRY_PATH):
                    import shutil
                    shutil.rmtree(REGISTRY_PATH)
                
                # Try primary URL first
                result = subprocess.run(
                    ["git", "clone", "--depth", "1", REGISTRY_URL, REGISTRY_PATH],
                    capture_output=True,
                    timeout=120,
                    text=True
                )
                if result.returncode == 0:
                    print("Successfully cloned DN42 registry from primary source")
                    return True
                else:
                    print(f"Failed to clone from primary source: {result.stderr}")
                    print("Trying fallback URL...")
                    
                    # Try fallback URL (GitHub mirror)
                    result = subprocess.run(
                        ["git", "clone", "--depth", "1", REGISTRY_URL_FALLBACK, REGISTRY_PATH],
                        capture_output=True,
                        timeout=120,
                        text=True
                    )
                    if result.returncode == 0:
                        print("Successfully cloned DN42 registry from fallback source (GitHub)")
                        return True
                    else:
                        print(f"Failed to clone from fallback source: {result.stderr}")
                        return False
            except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
                print(f"Error cloning registry: {e}")
                return False


def parse_registry_file(file_path: str) -> Dict[str, str]:
    """
    Parse a registry file and extract key-value pairs.
    
    Args:
        file_path: Path to the registry file
        
    Returns:
        Dict mapping keys to values
    """
    data = {}
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            current_key = None
            for line in f:
                line = line.rstrip('\n')
                # Skip comments and empty lines
                if line.startswith('#') or line.startswith('%') or not line.strip():
                    continue
                
                # Check if this is a key-value line
                if ':' in line:
                    parts = line.split(':', 1)
                    key = parts[0].strip()
                    value = parts[1].strip() if len(parts) > 1 else ""
                    
                    # Handle multi-line values
                    if key:
                        current_key = key
                        if current_key not in data:
                            data[current_key] = []
                        if value:
                            data[current_key].append(value)
                elif current_key and line.startswith((' ', '\t')):
                    # Continuation line
                    data[current_key].append(line.strip())
    except (IOError, OSError) as e:
        print(f"Error reading file {file_path}: {e}")
    
    # Convert lists to strings (join multiple values with comma for backwards compatibility)
    result = {}
    for key, values in data.items():
        if len(values) == 1:
            result[key] = values[0]
        elif len(values) > 1:
            result[key] = values[0]  # Take first value for consistency with old behavior
    
    return result


def find_asn_file(asn: int) -> Optional[str]:
    """
    Find the registry file for a given ASN.
    
    Args:
        asn: The ASN number
        
    Returns:
        Path to the file if found, None otherwise
    """
    if not os.path.exists(REGISTRY_PATH):
        return None
    
    # ASN files are stored in data/aut-num/
    asn_dir = os.path.join(REGISTRY_PATH, "data", "aut-num")
    if not os.path.exists(asn_dir):
        return None
    
    # ASN files are named like "AS4242420000" or "AS424242XXXX"
    asn_file = os.path.join(asn_dir, f"AS{asn}")
    if os.path.exists(asn_file):
        return asn_file
    
    return None


def find_person_file(person_id: str) -> Optional[str]:
    """
    Find the registry file for a given person/role.
    
    Args:
        person_id: The person or role identifier
        
    Returns:
        Path to the file if found, None otherwise
    """
    if not os.path.exists(REGISTRY_PATH):
        return None
    
    # Person files are stored in data/person/ and data/role/
    for subdir in ["person", "role"]:
        person_dir = os.path.join(REGISTRY_PATH, "data", subdir)
        if not os.path.exists(person_dir):
            continue
        
        person_file = os.path.join(person_dir, person_id)
        if os.path.exists(person_file):
            return person_file
    
    return None


def find_mntner_file(mntner_id: str) -> Optional[str]:
    """
    Find the registry file for a given maintainer.
    
    Args:
        mntner_id: The maintainer identifier
        
    Returns:
        Path to the file if found, None otherwise
    """
    if not os.path.exists(REGISTRY_PATH):
        return None
    
    # Maintainer files are stored in data/mntner/
    mntner_dir = os.path.join(REGISTRY_PATH, "data", "mntner")
    if not os.path.exists(mntner_dir):
        return None
    
    mntner_file = os.path.join(mntner_dir, mntner_id)
    if os.path.exists(mntner_file):
        return mntner_file
    
    return None


def get_whois_info_from_registry(query: str) -> Optional[str]:
    """
    Get whois information from local registry for a given query.
    
    Args:
        query: ASN (like "4242420000" or "AS4242420000") or other identifier
        
    Returns:
        Full whois text from the registry file, or None if not found
    """
    if not os.path.exists(REGISTRY_PATH):
        return None
    
    # Try to parse as ASN
    asn_str = query.upper()
    if asn_str.startswith("AS"):
        asn_str = asn_str[2:]
    
    try:
        asn = int(asn_str)
        file_path = find_asn_file(asn)
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read().strip()
            except (IOError, OSError) as e:
                print(f"Error reading ASN file {file_path}: {e}")
                return None
    except ValueError:
        # Not an ASN, try other types
        pass
    
    # Try as person/role
    file_path = find_person_file(query)
    if file_path:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read().strip()
        except (IOError, OSError) as e:
            print(f"Error reading person file {file_path}: {e}")
            return None
    
    # Try as maintainer
    file_path = find_mntner_file(query)
    if file_path:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read().strip()
        except (IOError, OSError) as e:
            print(f"Error reading mntner file {file_path}: {e}")
            return None
    
    return None


def get_asn_field(asn: int, field: str) -> Optional[str]:
    """
    Get a specific field value for an ASN from the local registry.
    
    Args:
        asn: The ASN number
        field: The field name (e.g., "mnt-by", "admin-c", "as-name")
        
    Returns:
        Field value if found, None otherwise
    """
    file_path = find_asn_file(asn)
    if not file_path:
        return None
    
    data = parse_registry_file(file_path)
    return data.get(field)


def list_all_asns() -> List[int]:
    """
    List all ASNs in the registry.
    
    Returns:
        List of ASN numbers
    """
    asns = []
    asn_dir = os.path.join(REGISTRY_PATH, "data", "aut-num")
    
    if not os.path.exists(asn_dir):
        return asns
    
    try:
        for filename in os.listdir(asn_dir):
            if filename.startswith("AS"):
                try:
                    asn = int(filename[2:])
                    asns.append(asn)
                except ValueError:
                    continue
    except (IOError, OSError) as e:
        print(f"Error listing ASNs: {e}")
    
    return sorted(asns)


# Initialize registry on module load (in background to avoid blocking)
def _init_registry():
    """Initialize registry in background thread."""
    try:
        ensure_registry_cloned()
    except Exception as e:
        print(f"Failed to initialize registry: {e}")


# Start initialization in background
_init_thread = threading.Thread(target=_init_registry, daemon=True)
_init_thread.start()
