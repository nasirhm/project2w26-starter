# CS 118 Winter 26 Project 2

- Completed handshake state machine in `security.c` for both client and server: Client Hello construction/parse, Server Hello construction/parse with certificate validation, handshake signature verification, and key derivation.
- Added certificate lifetime parsing and enforcement with required exit codes (1 for invalid/expired, 6 for malformed i/o).

## Build
```bash
cd project
make
```

## Run
Generate keys/certs first:
```bash
cd keys
./gen_files
```

Run server (from keys directory so relative paths to certs/keys work):
```bash
../../project/server 8080
```

Run client (new shell, also from keys directory):
```bash
../../project/client localhost 8080
```

## Tests
- Used provided helper to run full autograder suite: `./helper run` (passed at time of submission).

## Assumptions / Notes
- Hostname comparison uses the literal hostname string passed to the client against the DNS name in the certificate (null-terminated check enforced).
- Any malformed TLV or missing required field results in exit code 6 as specified; bad MAC exits with 5; bad handshake signature exits with 3.
- Time is taken from `time(NULL)`; failures to read time or invalid lifetimes exit with code 1.
