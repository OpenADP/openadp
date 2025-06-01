# OpenADP

Open source Advanced Data Protection for everyone

This project is recuiting!  Consider helping out!

## Motivation

WaywardGeek helped build [Gpogle's version of Advanced Data Protection](https://developer.android.com/about/versions/pie/security/ckv-whitepaper)
back in 2018.  Today, such systems [are under attack](https://www.bloomberg.com/news/articles/2025-02-21/apple-removes-end-to-end-encryption-feature-from-uk-after-backdoor-order).
There is a real threat that governments will order creation of secret mass surveillance backdoors like [what Yahoo was forced to build](https://www.reuters.com/article/technology/yahoo-secretly-scanned-customer-emails-for-us-intelligence-sources-idUSKCN1241YV/).
Existing systems defend backups from warrants, but there is no transparancy, and no way for the public to know if the system has been comprimized.

This is where OpenADP comes in.  All code will be 100% open source, and rather
than relying on proprietary HSMs, we'll used distributed trust.  Users don't
have to trust any particular OpenADP operator, just that a threshold of them
are honest.

When truned up, time, whole world will be able to securely E2EE encrypt their
data for free, protecting backups, passwords, message history, and more, if we
can get existing applications to talk to the new data protection service.

We need help, so please consider volunteering!  We know how to build the server,
which won't be too much work.  However, we'll need folks to run the server to
provide the distrubuted trust network.  Areas where we need help include:

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
operators in multiple countries to get access to any given users's keys. There
are cases where rational folks would agree to hand over that data, and we hope
we can end the encryption wars and develop sane public policies that protect
user data while offering a compromise where lives can be saved.

## High level design

The operator `*` here means scalar multiplication of an elliptic curve point.

Variables:

* UID: User ID string, typically an email address.
* DID: Device ID, a serialized gRPC protocol buffer describing the device.
* BID = HKDF(s, "Backup ID"): A backup ID used to identify a backup encrypted with `enc_key`.
* pin: Secret pin a user will easily remember, typically their phone unlock secret.
* H: Hash function mapping input parameters (with length prefixes) to a point
  on the curve, curve25519 to start.
* U = H(UID, DID, pin),  a point on the elliptic curve.
* s: A strong random secret value, 256 bits long.
* s[i[: The ith Shamir secret share of s.
* r: a random blinding factor in the range of [1..group order - 1].
* B = r\*U, A "blinded" point on the curve which has information theoretic
  security for `pin`.
* B[i] = s[i]\*B, shares fo B returned by OpenADP servers.
* w[i]: Weights used in [Shamir secret recovery]
* S = s\*U, a secret point on the curve from which we derive encryption keys.
  (https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing).
* enc\_key: The secret encryption key used to encrypted backed up data.
* N: The number of OpenADP servers used to protect s.
* T: The number of OpenADP servers that need to be online for the device to recover s.

THe steps involved by the device to backup data are:

* Cokmputes `U` and picks `s`.
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
tolerance, and low enouhg to allow 6 OpenADP servers to be offline.
"Partial" Byzantine fault tolerance means that that the attacker cannot control
the network long-term.

Once `s` is split into N shares with Shamir secret sharing, the device goes
through the registration protocol with servers  It uses TLS, terminated at
Cloudflare to talk to openadp.org.  The session is encrypted with a second
Noise-KK layer, where the server key is trusted by the client, and the client
key is trusted by the server.  The client gets its authentication key when
authenticating (how this works is TBD).

Over the Noise-KK second layer of encryption, the client sends a key share to
each of the OpenADP servers, which  can be anywhere it the world.  These
servers use Cloudflare Tunnels, which hides their IP address frome the client.

Each OpenADP server saves a record containing:

```
bytes UID  // User ID
bytes DID  // Device ID
bytes BID  // Backup ID
uint32 i  // The X position of the Shamir secret share.
bytes s[i] // The Y position of the Shamir secret share.
uint32 bad_guesses  // Initialized to 0.
uint32 max_guesses  // Usually 10.
bytes enc_s  // The secret s, encrypted with enc_key.
```

`UID` is the primary key, `DID` is the device ID, `s[i]` is the user's secret
share, `bad_guesses` is the number of times the user has attempted the recovey
flow, and `max_guesses` is the maximum number of attempts the client wants to
allow.

The only RPC provided for registration is `RegisterVault`.  All communication
with OpenADP servers is via gRPC, tunnled over Noise-KK, tunnled over TLS.

### Recovery

When a user no longer has access to their old device, and wants to recover
their backup from that device, their new device can use `ListValuts` to see the
device backups registered with OpenADP, and use the `OpenVault` RPC to obtain a
share of `S`.

The new device first calls ListValuts on all N servers, to see what vaults are
available on which servers.  The user is asked to pick an appropriate backup,
e.g. an Android backup for an Android device, and an iOS backup for an iOS
device.  The DID string should encode the inforemation needed in a format that
is TBD.

Once the user picks a backup to restore, they are asked for their secret pin,
or possibly an Android pattern if the user used their Android unlock pattern as
their secret.  Initially, we'll suppport pins.  The device then:

* Computes `U` with the users's guessed `pin`.
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
let (x[i], y[i]) = (i, s[i]*B) for each server i in the set of T servers that respnded.
let w[i] = product(j != i, x[i]/(x[i] - x[j])).
s*B = sum(w[i]s[i]*B)
```

A guess is known to be correct if i`enc_key` is able to decrypt `enc_s`.

Decrypting `s` also enables the device to reset the bad guess counter for the
backup just restored.

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

This scheme has a weakness, which is acceptible given the simplification this
scheme enjoys from nto requiring global conbsensus between OpenADP servers.
An attacker who can authenticate as the user can get more than 10 guesses.  In
a 9-of-15 scheme, at least 9 servers are required to participate in each
attempt.  The total attempts are 15\*10 = 150, so the attacker can get 16
guesses.  The user can also get more guesses, and can do OpenVault calls
serially  until `T` valid responses are recieved.  New guesses should be made
using servers with the lowest number of bad guessses.  The ListValuts RPC
returns this data.

### Partial Byzantine fault tolerance.

In a 9-of-15 scheme, if two OpenADP servers are compromized and under
control of the attacker, the protocol can complete correctly, and the attacker
lears nothing oth8er than 2 Shamir secret shares.

However, with 3 compromized nodes, if the attacker controls the network, they
can can split the honest nodes into two groups of 6, and add thei compromized
nodes to both groups.  The attacker can then make 20 guesses, 10 with each
group.  This splitting attack is worse for other systems, but isn't too bad for
OpenADP.
