#!/usr/bin/env python3
"""Check public locked crate versions against OSV. Development/CI only."""
import json
from pathlib import Path
import sys
import tomllib
import urllib.error
import urllib.request

lock = Path(__file__).resolve().parents[1] / 'Cargo.lock'
packages = [p for p in tomllib.loads(lock.read_text())['package']
            if p.get('source') == 'registry+https://github.com/rust-lang/crates.io-index']
queries = [{'package': {'ecosystem': 'crates.io', 'name': p['name']}, 'version': p['version']}
           for p in packages]
request = urllib.request.Request('https://api.osv.dev/v1/querybatch',
                                 data=json.dumps({'queries': queries}).encode(),
                                 headers={'Content-Type': 'application/json'})
try:
    with urllib.request.urlopen(request, timeout=40) as response:
        results = json.load(response)['results']
    if len(results) != len(packages):
        raise ValueError('incomplete batch')
    findings = [(p['name'], p['version'], v['id']) for p, result in zip(packages, results)
                for v in result.get('vulns', [])]
    if any(r.get('next_page_token') for r in results):
        raise ValueError('additional advisory pages')
except (OSError, KeyError, ValueError, urllib.error.URLError):
    sys.exit('UNKNOWN: OSV advisory check incomplete')
for finding in findings:
    print(*finding)
print(f'{len(packages)} locked registry packages checked, {len(findings)} advisory matches.')
sys.exit(bool(findings))
