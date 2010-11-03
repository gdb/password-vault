Description
-----------

The password vault stores encrypted data (typically shared passwords) on a
server. Users may then request the encrypted data and decrypt it locally. All
requests are logged and emailed for auditing purposes.

There are two machines involved in any transaction: the server (which holds the
encrypted passwords) and the client (the machine of a user requesting a
password). The password vault runs an HTTP daemon as the 'passwords' user on
the server; only the passwords user has access to the vault of encrypted
passwords. The client SSHs to the server as an unprivileged user [1] and sends
an HTTP request to the HTTP daemon either asking to list available passwords or
retrieve a specific password. The client can then display the retrieved list or
locally decrypt the retrieved password.

Security model
--------------

The server is not trusted to hold the plaintext passwords. The client machine
is trusted only enough to hold a transient copy of the encrypted and/or
plaintext passwords. Each password should be encrypted to the GPG public keys
of those users who need to be able to read them access.

This model seeks to mitigate the following types of threats:

- Client laptop is stolen. Then all the administrators need to do is remove access
  to the vault from that client, and/or re-encrypt the relevant password files. If
  the attacker manages to use the client machine's credentials to request a password
  before access is revoked, the request for the encrypted password would be emailed,
  yielding an audit trail.
- Server is compromised. No plaintext secrets ever touch the server, so this
  would reduce to the attack being able to break the encryption on the passwords.

The model also has the property that

- Secrets can be accessed from anywhere (although the server should be placed
  behind a VPN).

Setup
-----

I usually run the password-vault daemon as a service user
("passwords") via daemontools.

Bugs
----

- Can't handle large files.

[1] Clients should be assigned unique unprivileged users in order to maximize
the effectiveness of logging
