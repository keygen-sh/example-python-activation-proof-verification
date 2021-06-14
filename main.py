from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import base64
import sys
import os

# Cryptographically verify the activation proof using our public key
def verify_activation_proof(activation_proof):
  assert activation_proof, 'activation proof is missing'

  # Split Activation proof to obtain a dataset and signature, then decode
  # base64url encoded values
  signing_data, enc_sig = activation_proof.split('.')
  signing_prefix, enc_proof = signing_data.split('/')
  assert signing_prefix == 'proof', 'activation proof prefix %s is invalid' % signing_prefix

  proof = base64.urlsafe_b64decode(enc_proof)
  sig = base64.urlsafe_b64decode(enc_sig)

  # Load the PEM formatted public key from the environment
  pub_key = serialization.load_pem_public_key(
    os.environ['KEYGEN_PUBLIC_KEY'].encode(),
    backend=default_backend()
  )

  # Verify the proof
  try:
    pub_key.verify(
      sig,
      ("proof/%s" % enc_proof).encode(),
      padding.PKCS1v15(),
      hashes.SHA256()
    )

    print('[INFO] Activation proof contents: %s' % proof)

    return True
  except (InvalidSignature, TypeError):
    return False

try:
  ok = verify_activation_proof(
    sys.argv[1]
  )
except AssertionError as e:
  print('[ERROR] %s' % e)

  sys.exit(1)
except Exception as e:
  print('[ERROR] cryptography: %s' % e)

  sys.exit(1)

if ok:
  print('[OK] Activation proof is authentic!')

  sys.exit(0)
else:
  print('[ERROR] Activation proof is not authentic!')

  sys.exit(1)
