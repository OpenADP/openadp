# OpenADP

Open source Advanced Data Protection for everyone

This project is recruiting!  Consider helping out!

## Motivation

Today, systems like Apple's Advanced Data Protection [are under attack](https://www.bloomberg.com/news/articles/2025-02-21/apple-removes-end-to-end-encryption-feature-from-uk-after-backdoor-order).
There is a real threat that governments will order creation of secret mass surveillance backdoors like [what Yahoo was forced to build](https://www.reuters.com/article/technology/yahoo-secretly-scanned-customer-emails-for-us-intelligence-sources-idUSKCN1241YV/).
Existing systems defend backups from warrants, but there is no transparency, and no way for the public to know if the system has been compromised.

This is where OpenADP comes in.  All code will be 100% open source, and rather
than relying on proprietary HSMs, we'll use distributed trust.  Users don't
have to trust any particular OpenADP operator, just that a threshold of them
are honest.

When turned up, time, whole world will be able to securely E2EE encrypt their
data for free, protecting backups, passwords, message history, and more, if we
can get existing applications to talk to the new data protection service.

We need help, so please consider volunteering!  We know how to build the server,
which won't be too much work.  However, we'll need folks to run the server to
provide the distributed trust network.  Areas where we need help include:

* Running OpenADP servers. This is a T-of-N scheme, where users will need
  say 9 of 15 nodes to be available to recover their backups.
* Android client app, and preferably tight integration with the platform as an
* alternate backup service.
* Same with iOS
* Authentication. Users should register, and login before they can use any of
  their limited guesses to their phone unlock secret.

This system will provide nation-state resistance to secret back doors, and
eliminates secret mass surveillance, at least when it comes to data backed up
to the cloud. The UK and other governments will need to negotiate with
operators in multiple countries to get access to any given user's keys. There
are cases where rational folks would agree to hand over that data, and we hope
we can end the encryption wars and develop sane public policies that protect
user data while offering a compromise where lives can be saved.

## Getting Started

### The Ocrypt Password Hashing Library

The simplest way to use OpenADP is through the **Ocrypt** library - a drop-in replacement for traditional password hashing functions (bcrypt, scrypt, Argon2, PBKDF2) that provides distributed threshold cryptography.

**🔗 Ocrypt is now available as a separate library:**
- **Go**: `github.com/OpenADP/ocrypt` - [Repository](https://github.com/OpenADP/ocrypt)
- **Python**: `github.com/OpenADP/ocrypt-python` (coming soon)
- **JavaScript**: `github.com/OpenADP/ocrypt-js` (coming soon)

**Simple 2-function API:**
* `ocrypt.Register(user_id, app_id, long_term_secret, pin, max_guesses)` → metadata
* `ocrypt.Recover(metadata, pin)` → (long_term_secret, remaining_guesses, updated_metadata)

**Key Features:**
- **User-controlled secrets**: You provide the `longTermSecret` (e.g., ed25519 private key)
- **Distributed protection**: Secrets are split across multiple OpenADP servers
- **Guess limiting**: Built-in brute force protection with configurable attempts
- **Drop-in replacement**: Minimal changes to existing authentication code
- **Nation-state resistant**: No single point of failure

**Example Use Case - Go:**
```go
import "github.com/OpenADP/ocrypt/ocrypt"

// Protect private key with user's PIN
metadata, err := ocrypt.Register("user@example.com", "vault", privateKey, userPIN, 10)

// Later: recover private key to decrypt vault
privateKey, remaining, updatedMetadata, err := ocrypt.Recover(metadata, userPIN)
// Store updatedMetadata for future recoveries
```

See the [Ocrypt documentation](https://github.com/OpenADP/ocrypt) for installation instructions and detailed usage examples.

### Prerequisites

Before working with OpenADP, ensure you have the following installed:

- **Go** (version 1.18 or later) - for the main server implementation
- **Python 3** (version 3.7 or later) - for SDK and testing tools
- **Node.js** - for JavaScript SDK components
- **Make** - for building and running tests

### Environment Setup

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd openadp
   ```

2. **Set up Python virtual environment:**
   ```bash
   # Create a virtual environment
   python3 -m venv venv
   
   # Activate the virtual environment
   source venv/bin/activate
   
   # Install Python SDK dependencies
   pip install -r sdk/python/requirements.txt
   
   # Install the Python SDK in development mode (optional, for development)
   cd sdk/python && pip install -e . && cd ../..
   ```

3. **Build the Go components:**
   ```bash
   make build
   ```

4. **Verify your setup:**
   ```bash
   # Run all tests to ensure everything is working
   ./run_all_tests.py
   ```

### Quick Test

After setup, you should see all tests passing:
```bash
(.venv) $ ./run_all_tests.py
✅ Go build: PASS
✅ Go unit tests: PASS
✅ Go integration tests: PASS
...
📈 Total: 10 tests
✅ Passed: 10
```

### Important Notes for New Contributors

- **Always activate the virtual environment** before working with Python components: `source venv/bin/activate`
- The `(.venv)` prefix in your terminal prompt indicates the virtual environment is active
- If you see import errors or test failures, ensure you're in the activated virtual environment
- Run `./run_all_tests.py` after making changes to verify nothing is broken

### Troubleshooting

**"Virtual environment not found" error:**
```bash
# Make sure you created the venv in the project root directory
python3 -m venv venv
source venv/bin/activate
```

**Python import errors:**
```bash
# Ensure you're in the activated virtual environment and dependencies are installed
source venv/bin/activate
pip install -r sdk/python/requirements.txt
```

**Test failures after setup:**
```bash
# Verify your environment step by step
source venv/bin/activate        # Activate virtual environment
make build                      # Build Go components
./run_all_tests.py --verbose    # Run tests with detailed output
```

**Node.js/JavaScript related failures:**
```bash
# Ensure Node.js is installed and accessible
node --version
npm --version
```

## High level design

The operator `*` here means scalar multiplication of an elliptic curve point.

Variables:

* UID: User ID string, typically an email address.
* DID: Device ID, a serialized gRPC protocol buffer describing the device.
* BID: A backup ID used to identify a backup encrypted with `enc_key`.
* pin: Secret pin a user will easily remember, typically their phone unlock secret.
* H: Hash function mapping input parameters (with length prefixes) to a point
  on the curve, curve25519 to start.  It MUST produce points without known
  relationships to other points on the curve.
* U = H(UID, DID, BID, pin),  a point on the elliptic curve.
* s: A strong random secret value, 256 bits long.
* s[i]: The ith Shamir secret share of s.
* r: a random blinding factor in the range of [1..group order - 1].
* B = r\*U, A "blinded" point on the curve which has information theoretic
  security for `pin`.
* sB[i] = s[i]\*B, shares of B returned by OpenADP servers.
* w[i]: Weights used in [Shamir secret recovery]
* S = s\*U, a secret point on the curve from which we derive encryption keys.
  (https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing).
* enc\_key: The secret encryption key used to encrypted backed up data.
* N: The number of OpenADP servers used to protect s.
* T: The number of OpenADP servers that need to be online for the device to recover s.

The steps involved by the device to backup data are:

* Computes `U` and picks `s`.
* Computes `S = s*U`.
* Computes `enc_key = HKDF(S.x | S.y)`.
* Register `s` with `N` OpenADP servers.
* Encrypts backup data with `enc_key`.
* Sends the encrypted backup data to cloud storage somewhere.

### Registration

This is the step where the device secures `s` with OpenADP.  The device picks a
Shamir secret sharing scheme, Picking T and N, such as a 9-of-15 scheme.  15 is
nice, since it is divisible by 5, and we may want 5 countries hosting
OpenADP servers.  9 is high enough to give some partial-Byzantine fault
tolerance, and low enough to allow 6 OpenADP servers to be offline.
"Partial" Byzantine fault tolerance means that that the attacker cannot control
the network long-term.

Once `s` is split into N shares with Shamir secret sharing, the device goes
through the registration protocol with servers. It uses TLS, terminated at
Cloudflare to talk to openadp.org.  The session is encrypted with a second
Noise-NK layer, where the server key is trusted by the client, and the client
key is trusted by the server.  The client gets its authentication key when
authenticating (how this works is TBD).

Each OpenADP server saves a record containing:

```
bytes UID  // User ID
bytes DID  // Device ID
bytes BID  // Backup ID
uint32 x  // The X position of the Shamir secret share.
bytes y  // The s[i] Y position of the Shamir secret share.
uint32 bad_guesses  // Initialized to 0.
uint32 max_guesses  // Usually 10.
date expiration  // Date after which this record is deleted.
```

`UID` is the primary key, `DID` is the device ID, `s[i]` is the user's secret
share, `bad_guesses` is the number of times the user has attempted the recovery
flow, and `max_guesses` is the maximum number of attempts the client wants to
allow.

The only RPC provided for registration is `RegisterVault`.  All communication
with OpenADP servers is via gRPC, tunneled over Noise-NK, tunneled over TLS.

### Recovery

When a user no longer has access to their old device, and wants to recover
their backup from that device, their new device can use `ListVaults` to see the
device backups registered with OpenADP, and use the `OpenVault` RPC to obtain a
share of `S`.

The new device first calls `ListVaults` on all N servers, to see what vaults are
available on which servers.  The user is asked to pick an appropriate backup,
for example an Android backup for an Android device, and an iOS backup for an
Apple device.  The DID string should encode the information needed in a format
that is TBD.

Once the user picks a backup to restore, they are asked for their secret pin,
or possibly an Android pattern if the user used their Android unlock pattern as
their secret.  Initially, we'll support pins.  The device then:

* Computes `U` with the user's guessed `pin`.
* Picks a random blinding factor `r` in [1..group order - 1].
* Computes `B = r*U`
* Sends `UID`, selected `DID`, and `B` to each OpenADP server.
* Recieves at least `T` shares, which are tuples of the form `(i, s[i]*B)`.
* Recovers `s*B` from the shares using Shamir secret recovery.
* Recovers `S = (1/r)s*B`, where `1/r` is the modular inverse of `r`.
* Computes `enc_key = HKDF(S.x | S.y)`.
* Downloads the encrypted backup from cloud storage.
* Decrypts backup data with `enc_key`.

The secret, which  is `f(0)` on the Wikipedia page, is found using elliptic
curve scalar multiplication and addition:

```
let (x[i], y[i]) = (i, s[i]*B) for each server i in the set of T servers that responded.
let w[i] = product(j != i, x[i]/(x[i] - x[j])).
s*B = sum(w[i]s[i]*B)
```

A guess is known to be correct if `enc_key` is able to decrypt `enc_s`.

Decrypting `s` also enables the device to reset the bad guess counter for the
backup just restored.

### Key rotation

For the Advanced Data Protection use case, the right time for key rotation is
generally whenever there is a successful recover attempt.  How exactly this
should work depends on the application.

To cover the common use cases, take a look at some examples from [The Top Free
Encryption Software Tools in 2024](https://heimdalsecurity.com/blog/free-encryption-software-tools/):

#### Lastpass

If Lastpass were to offer Advanced Data Protection, they should certainly
consider OpenADP.  This eliminaes the risk of having all of yor Lastpass
passwords leaked when [Lastpass gets
hacked](https://www.upguard.com/blog/lastpass-vulnerability-and-future-of-password-security).

Password data like this can be long-lived, with expirations of OpenADP
registrations of say 5 years.  The data itself is small.  It is updated
frequently compared to recovery.  In this case, there should be a separate
metadata blob for the backup to OpenADP, containing:

```
{
  'private_key': <the private encryption key used to decrypt the passwords>
  'openadp_nodes': [<node1 URL>, <node2 URL>, ...],
  'threshold': <number of nodes requred for recovery>,
  ...  metadata needed by the Lastpass application.
}
```

This scheme allows a Lastpass user to encrypt data frequently to the public key
corresponding to `private_key`, without interacting with OpenADP.  When the
user does need to recover on a new device, they start using their limited (say
10) guesses.  On success, it is time for a key rotation.  A new public/private
key pair should be chosen for the new device Lastpass backups, and a new quorum
of OpenADP nodes should be chosen to protect the data.  In this case, we may
have one global backup for a given user, so UID, DID, and BID are the same for
each device.  The new registration automatically refreshes the quorum in case
some OpenADP nodes no longer work, and it resets the number of guesses back
to the desired maximum.  Metadata such as which nodes were used and the current
public backup key can be saved on Lastpass servers.

#### Bitlocker, VeraCrypt, FileVvalut2, DiskCryptor

Of these, Bitlocker is the only one that routinely hands your disk encryption
keys to authorities, since they are the only one that copies your disk
encryption keys to their cloud.  They are also in danger of being forced to do
secret mass surveillance.  Benefits of OpenADP for Bitlocker are clear.  The
others would still benefit from having strong encryption keys derived from weak
passwords or pins, which attackers can cheaply guess in most cases using GPUs.

The challenge here is decryption via OpenADP occurs every time the encrypted
volume is decrypted, and we don't want bad guesses to accumulate and hit the
maximum.  In this case, a new registration with OpenADP is needed after every
successful volume decryption.

The volume is too large to re-encrypt every time to a new key, so instead,
the actual disk encryption key is wrapped with `enc_key` and this encrypted
wrapped key is saved as metadata on the disk.  When `enc_key` is recovered,
it is used to unwrap the disk encryption key.

#### 7-Zip, AxCrypt

There are probably multiple use cases here, but the simple one is I just want
to encrypt my backup before I write it to a flash drive and stuff it in my
sock drawer.  In this case, never rotate the key.  There are maybe 10 guesses
available, period.  In this case, a strong legal password can be derived from
`enc_key`.

#### Backups of your phone's data

While Apple coined the term Advanced Data Protection, they rarely use it to
protect user data, and hand over many thousands of user backups to authorities
each year.  Their version has no ability to compromise on when to expose user
data, so they are stuck with mass secret surveillance as one extreme and no
data at all on the other, even when exposing it is clearly the right thing to
do.  There are clear benefits to switching to OpenADP.

Just like the case with full disk encryption, we need to wrap the actual
encryption key with `enc_key`.  If the device vendor is trying to sync
all data between devices all the time, then there can be just one
UID, DID, BID per user and device type (tablet, phone, or watch).
The key is probably the user's device unlock secret, which is rarely changed.
The wrapped unlock secret is simply synced between devices along with the
encrypted data, which can include contacts, message history, and application
data, etc.

To restore the number of remaining guesses back to the maximum after a
successful recovery, the new device should immediately re-register with
OpenADP, re-wrap their phone unlock secret with the new `enc_key`, and sync
this between devices when they come back online.  If any were online, then they
would not need to contact OpenADP for recovery in the first place.

## Security

The attacker wants to decrypt a backup which they have obtained from a user.
They do not know `s` and must allow messages on the network to eventually be
received.

The reason for the limitation on control of the network is that DoS is trivial
when the attacker controls the network.

### Limiting the number of guesses

Servers only allow OpenVault to be called up to `max_guesses` times, which is
probably 10 by default.  If the user fails this many times at a given server,
that server will return an error.

This scheme has a weakness, which is acceptable given the simplification this
scheme enjoys from not requiring global consensus between OpenADP servers.  An
attacker who can authenticate as the user can get more than 10 guesses.  In a
9-of-15 scheme, at least 9 servers are required to participate in each attempt.
The total attempts are 15\*10 = 150, so the attacker can get 16 guesses.  The
user can also get more guesses, and can do `OpenVault` calls serially  until `T`
valid responses are received.  New guesses should be made using servers with
the lowest number of bad guesses.  The `ListVaults` RPC returns this data.

### Partial Byzantine fault tolerance.

In a 9-of-15 scheme, if two OpenADP servers are compromised and under control
of the attacker, the protocol can complete correctly, and the attacker learns
nothing other than 2 Shamir secret shares.

However, with 3 compromised nodes, if the attacker controls the network, they
can can split the honest nodes into two groups of 6, and add their compromised
nodes to both groups.  The attacker can then make 20 guesses, 10 with each
group.  This splitting attack is worse for other systems, but isn't too bad for
OpenADP.

When a compromised node returns invalid points rather than `s[i]*B`,  then all
subsets of `T` responses should be checked to see if they result in a valid
solution.  Reporting bad nodes needs to be supported, and is TBD.

## Fake Keycloak (OIDC) Server for Integration Testing

A minimal OpenID Connect (OIDC) server is provided in `tests/fake_keycloak.py` for use in integration tests. It implements enough of the OIDC protocol to allow OpenADP clients to authenticate using the password grant, and issues real ES256-signed JWTs.

### Features
- Implements endpoints:
  - `/.well-known/openid-configuration`
  - `/protocol/openid-connect/token` (password grant)
  - `/protocol/openid-connect/certs` (JWKS)
- Configurable test users and clients (see top of `fake_keycloak.py`)
- Static EC key for JWT signing
- No external web frameworks required

### Requirements
- Python 3.7+
- `PyJWT`, `cryptography` (see `requirements.txt`)

### Usage

To run the server manually:

```bash
python tests/fake_keycloak.py
```

The server will listen on `http://localhost:9000/realms/openadp` by default. You can use this in your integration tests by pointing your OIDC discovery and token endpoints to this URL.

To use in test setup/teardown, import and start/stop the `FakeKeycloakServer` class:

```python
from tests.fake_keycloak import FakeKeycloakServer
server = FakeKeycloakServer()
server.start()
# ... run tests ...
server.stop()
```

## Documentation

For additional technical documentation, see the [`docs/`](docs/) directory:

- **[Client Cleanup Plan](docs/CLIENT_CLEANUP_PLAN.md)** - Comprehensive plan for preparing multi-language client implementations
- **[Client Interfaces](pkg/client/interfaces.go)** - Standardized interfaces for cross-language compatibility
- **[Documentation Index](docs/README.md)** - Complete documentation overview

### Development Status
- ✅ **Security Review**: Complete - no critical vulnerabilities found
- ✅ **Ed25519 Point Validation**: Implemented using cofactor clearing method  
- ✅ **Standardized Client Interfaces**: Ready for multi-language implementation
- 🔄 **Multi-Language Clients**: Ready to implement (Python, JavaScript, Java)

## Testing

OpenADP includes comprehensive tests across all components. **Before running tests, ensure you have completed the [environment setup](#environment-setup)** above.

```bash
# Activate virtual environment (if not already active)
source venv/bin/activate

# Run all tests
./run_all_tests.py

# Run only fast tests (skip integration tests)
./run_all_tests.py --fast

# Run only Go tests
./run_all_tests.py --go-only

# Run only Python tests
./run_all_tests.py --python-only

# Verbose output
./run_all_tests.py --verbose
```

### Noise-NK Cross-Platform Compatibility Test

OpenADP includes a dedicated test for cross-platform compatibility between the Python Noise-NK server and JavaScript client:

```bash
# Run the standalone Noise-NK compatibility test
./test_noise_nk_compatibility.py

# With verbose output
./test_noise_nk_compatibility.py --verbose

# Keep files for debugging (don't clean up server_info.json)
./test_noise_nk_compatibility.py --no-cleanup
```

This test:
- ✅ Verifies Node.js and Python dependencies
- 🚀 Starts a Python Noise-NK server automatically
- 🔗 Runs the JavaScript client against the server
- 📋 Tests complete handshake and secure message exchange
- 🧹 Cleans up processes and files automatically
- 📊 Reports detailed results and timing

The test is also integrated into the main test suite and runs automatically with `./run_all_tests.py`.
