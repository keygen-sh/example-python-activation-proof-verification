# Example Python Activation Proof Verification
This is an example of cryptographically verifying a machine activation proof,
and extracting embedded tamper-proof data within the proof for offline use, all by
using your Keygen account's public key. You can find your public key within
[your account's settings page](https://app.keygen.sh/settings).

## Running the example

First up, add an environment variable containing your public key:
```bash
# Your Keygen account's public key (make sure it is *exact* - newlines and all)
export KEYGEN_PUBLIC_KEY=$(printf %b \
  '-----BEGIN PUBLIC KEY-----\n' \
  'zdL8BgMFM7p7+FGEGuH1I0KBaMcB/RZZSUu4yTBMu0pJw2EWzr3CrOOiXQI3+6bA\n' \
  # …
  'efK41Ml6OwZB3tchqGmpuAsCEwEAaQ==\n' \
  '-----END PUBLIC KEY-----')
```

You can either run each line above within your terminal session before
starting the app, or you can add the above contents to your `~/.bashrc`
file and then run `source ~/.bashrc` after saving the file.

Next, install dependencies with [`pip`](https://packaging.python.org/):

```
pip install -r requirements.txt
```

Then run the script, passing in the `scheme` and `key` as arguments:

```bash
python main.py "proof/{ACTIVATION_PROOF}"
```

The proof's authenticity will be verified using RSA-SHA256 with the given
padding scheme. Be sure to copy your public key and proof correctly - your
keys will fail validation if these are copied or included incorrectly. You can
find your public key in [your account's settings](https://app.keygen.sh/settings).

## Questions?

Reach out at [support@keygen.sh](mailto:support@keygen.sh) if you have any
questions or concerns!
