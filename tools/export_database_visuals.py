#!/usr/bin/env python3
"""Export a read-only, sanitized PostgreSQL snapshot into the database explorer."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from urllib.parse import unquote, urlsplit

from update_blocklist import parse_env_file


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--images', action='store_true', help='also export high-resolution PNGs using Swift on macOS')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = root / 'docs' / 'database'
    config = parse_env_file(root / 'backend' / '.env.local')
    url = urlsplit(config['DATABASE_URL'])
    env = os.environ.copy()
    env.update(PGHOST=url.hostname or 'localhost', PGPORT=str(url.port or 5432),
               PGUSER=unquote(url.username or ''), PGPASSWORD=unquote(url.password or ''),
               PGDATABASE=unquote(url.path.lstrip('/')), PGCONNECT_TIMEOUT='5')
    result = subprocess.run(['psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-f',
                             str(output / 'snapshot.sql')], env=env, capture_output=True, text=True)
    if result.returncode:
        print('Database snapshot failed. Check local PostgreSQL and backend/.env.local.', file=sys.stderr)
        return 1
    data = json.loads(result.stdout)
    encoded = json.dumps(data, ensure_ascii=True).replace('<', '\\u003c')
    template = (output / 'explorer.template.html').read_text()
    (output / 'index.html').write_text(template.replace('__SNAPSHOT_JSON__', encoded))
    (output / 'snapshot.json').write_text(json.dumps(data, indent=2) + '\n')
    print(f"Database explorer refreshed at {data['snapshot_at']}")
    print(output / 'index.html')
    if args.images:
        subprocess.run(['swift', '-module-cache-path', '/private/tmp/esp32dns-swift-cache',
                        str(root / 'tools' / 'render_database_visuals.swift'), str(output)], check=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
