## Requirements
Install dev requirements from https://github.com/theupdateframework/tuf

This demo uses features that are not yet in the develop branch:
* https://github.com/theupdateframework/tuf/pull/1106
* https://github.com/theupdateframework/tuf/pull/1103/files

A branch with both of these features, plus a few bug fixes is available at
https://github.com/mnm678/tuf/tree/notarydemo

## Setup
Run:
* python demo.py
* cp -r "registry/metadata.staged/" "registry/metadata"

Create the following client tree using the generated root metadata
tufrepo
- metadata
  - current
    - root.json
  - previous

in registry, run python -m http.server 8001

download from client using:
client.py --repo http://localhost:8001 [--map_file map_file] target_path

