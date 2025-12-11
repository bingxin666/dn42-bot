# DN42 Registry Local Clone Module

## Overview

This module (`registry.py`) manages a local clone of the DN42 registry and provides functions to query it efficiently. The whois logic has been refactored to use this local registry first before falling back to remote whois servers.

## Key Features

1. **Automatic Registry Cloning**: On startup, the module automatically clones the DN42 registry to `./cache/registry`
2. **Fallback Support**: If the primary DN42 git server is unavailable, it falls back to GitHub mirror
3. **Fast Local Lookups**: All whois queries check the local registry first, avoiding network delays
4. **Cache Management**: Uses existing whois cache system for frequently accessed data
5. **Backward Compatibility**: Falls back to traditional whois commands if data is not in local registry

## How It Works

### Initialization

When the module is imported, it starts a background thread to clone the DN42 registry:

```python
from tools import registry

# Registry is automatically initialized in background
# Clones to ./cache/registry by default
```

### Registry Structure

The DN42 registry is organized as follows:
```
./cache/registry/
└── data/
    ├── aut-num/     # ASN records (e.g., AS4242420000)
    ├── person/      # Person records
    ├── role/        # Role records
    ├── mntner/      # Maintainer records
    ├── route/       # IPv4 route objects
    └── route6/      # IPv6 route objects
```

### Main Functions

#### `ensure_registry_cloned() -> bool`
Ensures the registry is cloned and up-to-date. Called automatically on module import.

#### `get_whois_info_from_registry(query: str) -> Optional[str]`
Gets full whois information for an ASN, person, or maintainer from the local registry.

```python
# Query by ASN
whois_text = registry.get_whois_info_from_registry("4242420000")
# or
whois_text = registry.get_whois_info_from_registry("AS4242420000")

# Query by person/role
whois_text = registry.get_whois_info_from_registry("PERSON-DN42")

# Query by maintainer
whois_text = registry.get_whois_info_from_registry("SOME-MNT")
```

#### `get_asn_field(asn: int, field: str) -> Optional[str]`
Gets a specific field from an ASN record.

```python
mnt_by = registry.get_asn_field(4242420000, "mnt-by")
as_name = registry.get_asn_field(4242420000, "as-name")
admin_c = registry.get_asn_field(4242420000, "admin-c")
```

#### `list_all_asns() -> List[int]`
Lists all ASNs in the registry.

```python
all_asns = registry.list_all_asns()
print(f"Found {len(all_asns)} ASNs in registry")
```

## Integration with Existing Code

### Modified Functions

1. **`tools.get_whoisinfo_by_asn(asn, item=...)`**
   - Now checks local registry first before calling whois command
   - Maintains same cache behavior
   - Falls back to whois command if registry lookup fails

2. **`tools.extract_asn(text, *, privilege=False)`**
   - Checks local registry to verify ASN exists
   - Falls back to whois command if needed
   - Handles ASN normalization (e.g., 1080 → 4242421080)

3. **`/whois` command**
   - Queries local registry first
   - Handles ASN normalization automatically
   - Falls back to whois command for non-DN42 queries or if not found

4. **`login.get_email(asn)`**
   - Uses local registry to get admin-c information
   - Falls back to whois command if needed

## Performance Benefits

1. **Faster Lookups**: No network round-trip for most queries
2. **Reduced Load**: Less load on DN42 whois servers
3. **Offline Capability**: Can work without network access to DN42 whois servers
4. **Batch Operations**: Efficient when processing multiple ASNs

## Configuration

The registry module uses these configuration values:

```python
REGISTRY_URL = "https://git.dn42.dev/dn42/registry.git"  # Primary source
REGISTRY_URL_FALLBACK = "https://github.com/dn42/registry.git"  # Fallback (if exists)
CACHE_DIR = "./cache"  # Cache directory
REGISTRY_PATH = "./cache/registry"  # Registry clone location
```

## Updating the Registry

The registry is automatically updated on server restart. To manually update:

```python
from tools import registry
result = registry.ensure_registry_cloned()
# This will pull latest changes
```

For production deployments, consider:
1. Setting up a cron job to periodically update the registry
2. Monitoring the registry update process
3. Having a fallback mechanism if updates fail

## Error Handling

The module gracefully handles:
- Network failures during clone/update
- Missing files in the registry
- Corrupted or malformed registry files
- Permission errors

All errors are logged and the system falls back to traditional whois commands.

## Testing

Run the included test suite:

```bash
# Test basic registry functionality
python3 /tmp/test_registry2.py

# Test tools integration
python3 /tmp/test_tools_integration.py
```

## Notes

- The `/cache` directory is added to `.gitignore`
- First-time clone may take 1-2 minutes depending on connection speed
- The registry uses shallow clone (`--depth 1`) to save space
- Background initialization prevents blocking bot startup
