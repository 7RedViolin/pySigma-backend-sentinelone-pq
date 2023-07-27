# pySigma-backend-sentinelone-pq
![Tests](https://github.com/7RedViolin/pysigma-backend-sentinelone-pq/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/7RedViolin/52570ccc8af436c7ab34b942d1839ce0/raw/7RedViolin-pySigma-backend-sentinelone-pq.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma SentinelOne PQ Backend

This is the SentinelOne PowerQuery (PQ) backend for pySigma. It provides the package `sigma.backends.sentinelone` with the `SentinelOnePQBackend` class.
Further, it contains the processing pipelines in `sigma.pipelines.sentinelone` for field renames and error handling. This pipeline is automatically applied to `SigmaRule` and `SigmaCollection` objects passed to the `SentinelOnePQBackend` class.

It supports the following output formats:

* default: plaintext queries
* json: JSON formatted queries that includes the query, rule name, rule ID, and rule description

This backend is currently maintained by:

* [Cori Smith](https://github.com/7RedViolin/)

## Installation
This can be install via pip from PyPI or using pySigma's plugin functionality

### PyPI
```bash
pip install pysigma-backend-sentinelone-pq
```

### pySigma
```python
from sigma.plugins import SigmaPluginDirectory
plugins = SigmaPluginDirectory.default_plugin_directory()
plugins.get_plugin_by_id("sentinelone_pq").install()
```

## Usage

### sigma-cli
```bash
sigma convert -t sentinelone_pq proc_creation_win_office_onenote_susp_child_processes.yml
```

### pySigma
```python
from sigma.backends.sentinelone_pq import SentinelOnePQBackend
from sigma.rule import SigmaRule

rule = SigmaRule.from_yaml("""
title: Invoke-Mimikatz CommandLine
status: test
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        CommandLine|contains: Invoke-Mimikatz
    condition: sel""")


backend = SentinelOnePQBackend()
print(backend.convert_rule(rule)[0])
```

## Side Notes & Limitations
- Backend uses PowerQuery syntax
- Pipeline uses PowerQuery field names
- Pipeline supports `linux`, `windows`, and `macos` product types
- Pipeline supports the following category types for field mappings
  - `process_creation`
  - `file_event`
  - `file_change`
  - `file_rename`
  - `file_delete`
  - `image_load`
  - `pipe_creation`
  - `registry_add`
  - `registry_delete`
  - `registry_event`
  - `registry_set`
  - `dns_query`
  - `dns`
  - `network_connection`
  - `firewall`
- Any unsupported fields or categories will throw errors
