"""
Usage
  nv2.py --sign rolename keypath
  nv2.py --publish
  nv2.py --revoke rolename keypath
  nv2.py --rotate rolename oldkeypath newkeypath
  nv2.py --add rolename targetpath keypath
"""

import os
import sys
import argparse
import shutil

import tuf
import tuf.repository_tool as repo_tool
import tuf.scripts

import securesystemslib

PROG_NAME = 'nv2'

REPO_DIR = 'registry'
KEYSTORE_DIR = 'keystore'

ROOT_KEY_NAME = 'root_key'
ROOT2_KEY_NAME = 'root_key2'
TARGETS_KEY_NAME = 'targets_key'
SNAPSHOT_KEY_NAME = 'snapshot_key'
TIMESTAMP_KEY_NAME = 'timestamp_key'
# This is used for the key rotation demo
# TIMESTAMP_KEY_NAME = 'snapshot_key'

STAGED_METADATA_DIR = 'metadata.staged'
METADATA_DIR = 'metadata'

def process_command_line_arguments(parsed_arguments):
  if not isinstance(parsed_arguments, argparse.Namespace):
    raise tuf.exceptions.Error('Invalid namespace: ' + repr(parsed_arguments))

  if parsed_arguments.sign:
    sign_role(parsed_arguments)

  if parsed_arguments.publish:
    publish_registry(parsed_arguments)

  if parsed_arguments.revoke:
    revoke_key(parsed_arguments)

  if parsed_arguments.rotate:
    rotate_key(parsed_arguments)

  if parsed_arguments.add:
    add_target(parsed_arguments)

def parse_arguments():
  parser = argparse.ArgumentParser()

  parser.add_argument('--sign', type=str, nargs=2)

  parser.add_argument('--publish', action='store_true')

  parser.add_argument('--revoke', type=str, nargs=2)

  parser.add_argument('--rotate', type=str, nargs=3)

  parser.add_argument('--add', '--add-target', type=str, nargs=3)

  parsed_args = parser.parse_args()

  return parsed_args

def sign_role(parsed_arguments):
  registry = repo_tool.load_repository(REPO_DIR)

  role = parsed_arguments.sign[0]
  keypath = parsed_arguments.sign[1]

  password = securesystemslib.interface.get_password('Enter a password for'
      ' the encrypted key (' + repr(keypath) + '): ', confirm=False)

  encrypted_key = None
  with open(keypath, 'rb') as file_object:
    encrypted_key = file_object.read().decode('utf-8')

  role_privatekey = securesystemslib.keys.decrypt_key(encrypted_key, password)

  if role == 'targets':
    registry.targets.load_signing_key(role_privatekey)
  elif role == 'root':
    registry.root.load_signing_key(role_privatekey)
  elif role == 'snapshot':
    registry.snapshot.load_signing_key(role_privatekey)
  elif role == 'timestamp':
    registry.timestamp.load_signing_key(role_privatekey)
  else:
    registry.targets(role).load_signing_key(role_privatekey)

    targets_keypath = os.path.join(KEYSTORE_DIR, TARGETS_KEY_NAME)
    password = securesystemslib.interface.get_password('Enter a password for'
        ' the encrypted key (' + repr(targets_keypath) + '): ', confirm=False)

    encrypted_key = None
    with open(targets_keypath, 'rb') as file_object:
      encrypted_key = file_object.read().decode('utf-8')
    targets_privatekey = securesystemslib.keys.decrypt_key(encrypted_key, password)

    registry.targets.load_signing_key(targets_privatekey)

    registry.write(role, increment_version_number=True)
    registry.write('targets', increment_version_number=True)


  # write the role that was signed. a call to --publish will write the
  # top-level metadata
  registry.writeall(snapshot_merkle=True)


def publish_registry(parsed_arguments):
  registry = repo_tool.load_repository(REPO_DIR)

  snapshot_keypath = os.path.join(KEYSTORE_DIR, SNAPSHOT_KEY_NAME)
  timestamp_keypath = os.path.join(KEYSTORE_DIR, TIMESTAMP_KEY_NAME)
  snapshot_password = 'password'

  encrypted_key = None
  with open(snapshot_keypath, 'rb') as file_object:
    encrypted_key = file_object.read().decode('utf-8')

  snapshot_private = securesystemslib.keys.decrypt_key(encrypted_key, snapshot_password)

  timestamp_password='password'
  encrypted_key = None
  with open(timestamp_keypath, 'rb') as file_object:
    encrypted_key = file_object.read().decode('utf-8')

  timestamp_private = securesystemslib.keys.decrypt_key(encrypted_key, timestamp_password)

  registry.snapshot.load_signing_key(snapshot_private)
  registry.timestamp.load_signing_key(timestamp_private)

  registry.writeall(snapshot_merkle=True)

  staged_dir = os.path.join(REPO_DIR, STAGED_METADATA_DIR)
  live_dir = os.path.join(REPO_DIR, METADATA_DIR)

  shutil.rmtree(live_dir, ignore_errors=True)
  shutil.copytree(staged_dir, live_dir)




def revoke_key(parsed_arguments):
  registry = repo_tool.load_repository(REPO_DIR)

  role = parsed_arguments.revoke[0]
  keypath = parsed_arguments.revoke[1]

  key_metadata = securesystemslib.util.load_json_file(keypath)
  keyobject, junk = securesystemslib.keys.format_metadata_to_key(key_metadata)

  if role == 'root':
    registry.root.remove_verification_key(keyobject)
  elif role == 'targets':
    registry.targets.remove_verification_key(keyobject)
  elif role == 'snapshot':
    registry.snapshot.remove_verification_key(keyobject)
  elif role == 'timestamp':
    registry.timestamp.remove_verification_key(keyobject)
  else:
    registry.targets(role)._parent_targets_object.revoke(role)


  if role in ('root', 'targets', 'snapshot', 'timestamp'):
    root_keypath = os.path.join(KEYSTORE_DIR, ROOT_KEY_NAME)
    password = securesystemslib.interface.get_password('Enter a password for'
        ' the encrypted key (' + repr(root_keypath) + '): ', confirm=False)
    encrypted_key = None
    with open(root_keypath, 'rb') as file_object:
      encrypted_key = file_object.read().decode('utf-8')

    root_private = securesystemslib.keys.decrypt_key(encrypted_key, password)

    registry.root.load_signing_key(root_private)

  publish_registry(parsed_arguments)



def rotate_key(parsed_arguments):
  registry = repo_tool.load_repository(REPO_DIR)

  role = parsed_arguments.rotate[0]
  old_keypath = parsed_arguments.rotate[1]
  new_keypath = parsed_arguments.rotate[2]

  key_metadata = securesystemslib.util.load_json_file(old_keypath)
  old_keyobject, junk = securesystemslib.keys.format_metadata_to_key(key_metadata)

  key_metadata = securesystemslib.util.load_json_file(new_keypath)
  new_keyobject, junk = securesystemslib.keys.format_metadata_to_key(key_metadata)

  if role == 'root':
    registry.root.remove_verification_key(old_keyobject)
    registry.root.add_verification_key(new_keyobject)

  elif role == 'targets':
    registry.targets.remove_verification_key(old_keyobject)
    registry.targets.add_verification_key(new_keyobject)
    TARGETS_KEY_NAME = os.path.basename(new_keypath[:-len('.pub')])

  elif role == 'snapshot':
    registry.snapshot.remove_verification_key(old_keyobject)
    registry.snapshot.add_verification_key(new_keyobject)
    SNAPSHOT_KEY_NAME = os.path.basename(new_keypath[:-len('.pub')])

  elif role == 'timestamp':
    registry.timestamp.remove_verification_key(old_keyobject)
    registry.timestamp.add_verification_key(new_keyobject)
    TIMESTAMP_KEY_NAME = os.path.basename(new_keypath[:-len('.pub')])
    print(TIMESTAMP_KEY_NAME)

  else:
    registry.targets(role)._parent_targets_object.remove_verification_key(old_keyobject)
    registry.targets(role)._parent_targets_object.add_verification_key(new_keyobject)

  if role in ('root', 'targets', 'snapshot', 'timestamp'):
    root_keypath = os.path.join(KEYSTORE_DIR, ROOT_KEY_NAME)
    password = securesystemslib.interface.get_password('Enter a password for'
        ' the encrypted key (' + repr(root_keypath) + '): ', confirm=False)
    root_private = repo_tool.import_rsa_privatekey_from_file("keystore/root_key", password=password)
    root_keypath = os.path.join(KEYSTORE_DIR, ROOT2_KEY_NAME)
    password = securesystemslib.interface.get_password('Enter a password for'
        ' the encrypted key (' + repr(root_keypath) + '): ', confirm=False)

    root_private2 = repo_tool.import_rsa_privatekey_from_file("keystore/root_key2", password=password)

    registry.root.load_signing_key(root_private)
    registry.root.load_signing_key(root_private2)

    registry.write('root', increment_version_number=True)


def add_target(parsed_arguments):
  registry = repo_tool.load_repository(REPO_DIR)

  role = parsed_arguments.add[0]
  filepath = parsed_arguments.add[1]
  keypath = parsed_arguments.add[2]

  registry.targets(role).add_target(filepath)

  password = securesystemslib.interface.get_password('Enter a password for'
      ' the encrypted key (' + repr(keypath) + '): ', confirm=False)
  role_key = repo_tool.import_ed25519_privatekey_from_file(keypath, password=password)

  registry.targets(role).load_signing_key(role_key)

  registry.writeall(snapshot_merkle=True)







if __name__ == '__main__':
  arguments = parse_arguments()

  process_command_line_arguments(arguments)
