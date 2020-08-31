from tuf.repository_tool import *

# For more documentation about the commands used in this setup, see
# https://github.com/theupdateframework/tuf/blob/develop/docs/TUTORIAL.md

def generate_keys():
  # Writes keys to keystore/*
  # Creates 2 root keys, one key for all other top level roles

  generate_and_write_rsa_keypair("keystore/root_key", bits=2048, password="password")
  generate_and_write_rsa_keypair("keystore/root_key2", bits=2048, password="password")
  generate_and_write_ed25519_keypair('keystore/targets_key', password='password')
  generate_and_write_ed25519_keypair('keystore/snapshot_key', password='password')
  generate_and_write_ed25519_keypair('keystore/timestamp_key', password='password')

  # Also create additional role keys for delegations
  generate_and_write_ed25519_keypair('keystore/wabbit_networks_key', password='password')
  generate_and_write_ed25519_keypair('keystore/my_repo_key', password='password')


def create_registry():
  # uses top level keys from keystore/*

  # Load keys
  public_root_key = import_rsa_publickey_from_file("keystore/root_key.pub")
  public_root_key2 = import_rsa_publickey_from_file("keystore/root_key2.pub")
  private_root_key = import_rsa_privatekey_from_file("keystore/root_key", password="password")
  private_root_key2 = import_rsa_privatekey_from_file("keystore/root_key2", password="password")

  public_targets_key = import_ed25519_publickey_from_file("keystore/targets_key.pub")
  public_snapshot_key = import_ed25519_publickey_from_file("keystore/snapshot_key.pub")
  public_timestamp_key = import_ed25519_publickey_from_file("keystore/timestamp_key.pub")
  private_targets_key = import_ed25519_privatekey_from_file("keystore/targets_key", password="password")
  private_snapshot_key = import_ed25519_privatekey_from_file("keystore/snapshot_key", password="password")
  private_timestamp_key = import_ed25519_privatekey_from_file("keystore/timestamp_key", password="password")


  # Create registry and root
  registry = create_new_repository("registry")
  registry.root.add_verification_key(public_root_key)
  registry.root.add_verification_key(public_root_key2)
  registry.root.threshold=2

  registry.root.load_signing_key(private_root_key)
  registry.root.load_signing_key(private_root_key2)

  # Create top-level roles
  registry.targets.add_verification_key(public_targets_key)
  registry.snapshot.add_verification_key(public_snapshot_key)
  registry.timestamp.add_verification_key(public_timestamp_key)

  registry.targets.load_signing_key(private_targets_key)
  registry.snapshot.load_signing_key(private_snapshot_key)
  registry.timestamp.load_signing_key(private_timestamp_key)

  # For demo purposes, set long expirations
  registry.timestamp.expiration = datetime.datetime(2080, 10, 28, 12, 8)
  registry.snapshot.expiration = datetime.datetime(2080, 10, 28, 12, 8)

  # Import delegated keys
  public_wabbit_networks_key = import_ed25519_publickey_from_file("keystore/wabbit_networks_key.pub")
  private_wabbit_networks_key = import_ed25519_privatekey_from_file("keystore/wabbit_networks_key", password="password")
  public_my_repo_key = import_ed25519_publickey_from_file("keystore/my_repo_key.pub")
  private_my_repo_key = import_ed25519_privatekey_from_file("keystore/my_repo_key", password="password")

  # Delegate to the wabbit_networks repository and add initial image
  registry.targets.delegate('wabbit_networks', [public_wabbit_networks_key], ['wabbit_networks/*'])
  registry.targets('wabbit_networks').add_target("wabbit_networks/file1.txt")
  registry.targets('wabbit_networks').load_signing_key(private_wabbit_networks_key)

  # Delegate to my_repo and add initial image
  registry.targets.delegate('my_repo', [public_my_repo_key], ['my_repo/*'])
  registry.targets('my_repo').add_target("my_repo/image1")
  registry.targets('my_repo').load_signing_key(private_my_repo_key)


  registry.mark_dirty(['root', 'snapshot', 'targets','timestamp', 'wabbit_networks', 'my_repo'])

  registry.writeall(snapshot_merkle=True)


def large_snapshot_demo():
  registry = load_repository('registry')

  public_my_repo_key = import_ed25519_publickey_from_file("keystore/my_repo_key.pub")
  private_my_repo_key = import_ed25519_privatekey_from_file("keystore/my_repo_key", password="password")

  path = 'registry/targets/'
  # Create 16 directories with targets files
  # and add them to targets
  for i in range(16):
    dirname = 'repository' + str(i)
    filename = 'file' + str(i)
    filepath = os.path.join(path, dirname, filename)
    securesystemslib.util.ensure_parent_dir(filepath)
    with open(filepath, 'wt') as f:
      f.write('This is an example signed file')

    registry.targets.delegate(dirname, [public_my_repo_key],
        [os.path.join(dirname, '*')])
    registry.targets(dirname).add_target(os.path.join(dirname, filename))
    registry.targets(dirname).load_signing_key(private_my_repo_key)


  # load keys for targets, snapshot, timestamp

  public_targets_key = import_ed25519_publickey_from_file("keystore/targets_key.pub")
  public_snapshot_key = import_ed25519_publickey_from_file("keystore/snapshot_key.pub")
  public_timestamp_key = import_ed25519_publickey_from_file("keystore/timestamp_key.pub")
  private_targets_key = import_ed25519_privatekey_from_file("keystore/targets_key", password="password")
  private_snapshot_key = import_ed25519_privatekey_from_file("keystore/snapshot_key", password="password")
  private_timestamp_key = import_ed25519_privatekey_from_file("keystore/timestamp_key", password="password")

  registry.targets.load_signing_key(private_targets_key)
  registry.snapshot.load_signing_key(private_snapshot_key)
  registry.timestamp.load_signing_key(private_timestamp_key)

  registry.mark_dirty(['snapshot', 'targets','timestamp', 'my_repo'])
  registry.writeall(snapshot_merkle=True)





if __name__ == '__main__':
  # If keys are re-generated, updated targets_map.json as well
   generate_keys()
  create_registry()
  large_snapshot_demo()
