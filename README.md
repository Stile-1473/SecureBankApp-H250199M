# Secure Banking Application

![build](https://github.com/Stile-1473/SecureBankApp-H250199M/actions/workflows/build.yml/badge.svg)

A console-based banking application in Java that lets customers register, log in, open accounts, deposit, withdraw and view their transaction history. It is built to show object-oriented design and secure coding practices: hashed credentials, brute-force protection, strict input validation, access control on every operation, and tamper-evident file storage.

## Student Details

- **Name:** Kudakwashe Stiles Chishowerere
- **Registration Number:** H250199M
- **Course:** ISS 2101, Information Security and Assurance, Harare Institute of Technology

## Features

**Banking**
- Register a customer and log in
- Open up to 3 bank accounts per customer
- View accounts and balances
- Deposit and withdraw funds
- View the transaction history for each account
- All data is saved to text files and loaded again on start-up

**Security**
- Passwords hashed with PBKDF2-HMAC-SHA256, a unique random salt per user and 600,000 iterations
- Password policy: 12 to 128 characters, at least 3 character types, blocklist of common words, no username, no runs like `aaaa` or `1234`
- Brute-force protection: account locks after 5 failed attempts for 1, 2, 4, 8 and then 15 minutes; the lock survives restarts
- Identical error message and timing for every login failure, so attackers cannot discover which usernames exist
- Passwords typed with hidden input, held as `char[]` and wiped from memory after use
- Sessions expire after 5 minutes idle or 30 minutes in total
- Withdrawals over USD 1,000 require the password again
- Ownership check on every account operation; another customer's account looks exactly like one that does not exist
- Money stored as `BigDecimal` with exactly 2 decimal places; zero, negative, over-precise and scientific-notation amounts are rejected
- Limits: USD 10,000 per transaction, USD 5,000 withdrawn per 24 hours across all of a customer's accounts
- Random, non-sequential 10-digit account numbers with a Luhn check digit
- HMAC-SHA256 on every data file: edits made outside the app are detected and the app refuses to start
- Hash-chained transaction history: altering, deleting, inserting or reordering any past transaction is detected
- Start-up reconciliation: every balance must equal the replay of its transaction history
- Crash-safe atomic file writes, owner-only file permissions, and a lock that stops two copies running at once
- Security audit log of logins, lockouts, access-denied attempts and transactions, with masked account numbers and log-injection protection
- 86 automated tests, run on every push by GitHub Actions

## How to Run

Requires **JDK 21 or newer** and **Maven 3.9+**.

```bash
git clone https://github.com/Stile-1473/SecureBankApp-H250199M.git
cd SecureBankApp-H250199M
mvn clean package
java -jar target/securebank.jar
```

Run it from a real terminal (Command Prompt, PowerShell, macOS/Linux terminal, or IntelliJ's *Terminal* tab), not an IDE "Run" window. The app needs a real console to hide password input and will refuse to start without one.

### First run of a fresh clone

The HMAC key (`data/.secret.key`) is deliberately **not** in the repository, because anyone holding it could forge the data files. On a fresh clone the app therefore finds data files it cannot verify, and asks:

```
WARNING: No integrity key was found, but data files exist.
Type TRUST to accept and re-sign the existing files:
```

Type `TRUST`. The app creates a new key and re-signs the files. The hash chain and balance checks still run, so tampered demo data is still rejected. On every later start no prompt appears.

### Demo account

The repository includes demo data so the app can be tried straight away:

| Username | Password | Account | Balance |
|---|---|---|---|
| `demo_user` | `Kariba#Sunset47` | `6253940073` | USD 1,300.00 |

This is a throwaway demo credential. Only its salted PBKDF2 hash is stored in `data/users.txt`.

### Run the tests

```bash
mvn verify
```

## Security Design

### Threat model (STRIDE)

| Threat | Example attack | Controls in this project |
|---|---|---|
| **Spoofing** | Guessing a customer's password | PBKDF2 with 600,000 iterations; password policy; lockout with increasing duration; lockout state saved to disk |
| **Spoofing** | Finding valid usernames to target | Same message and same hashing time for every login failure (`PasswordHasher.dummyVerify`) |
| **Spoofing** | Using a terminal someone left logged in | Idle and maximum session timeouts; password re-entry for withdrawals over USD 1,000; 5 wrong re-entries lock the account and end the session |
| **Tampering** | Editing a balance in `accounts.txt` | HMAC-SHA256 per file; start-up balance reconciliation |
| **Tampering** | Deleting or changing a past transaction | SHA-256 hash chain over `transactions.txt`, checked on every start |
| **Tampering** | Depositing `-500` or `1e9` | Whitelist regex before parsing; `BigDecimal` with strict scale; positive-only amounts; limits |
| **Tampering** | Injecting `|` or a newline to forge records | Usernames, amounts and account numbers are whitelisted; the file writer rejects newlines and `#` |
| **Repudiation** | "I never made that withdrawal" | Append-only transaction history; audit log of logins and transactions |
| **Information disclosure** | Stolen `users.txt` | No plain passwords stored, only salted slow hashes |
| **Information disclosure** | Reading another customer's balance (IDOR) | Ownership check in the service layer on every operation |
| **Information disclosure** | Error messages leaking internals | One generic handler; no stack traces shown; `toString()` never prints secrets; account numbers masked in logs |
| **Denial of service** | Locking a victim out permanently | Locks are temporary, so repeated wrong guesses cannot shut a customer out for good |
| **Denial of service** | Huge input to make hashing slow | Password length capped at 128 characters |
| **Elevation of privilege** | Acting on another user's data | Every service method checks the session and ownership before acting; the UI is never trusted to enforce security |

### Defence in depth for stored data

1. **HMAC-SHA256** detects any change made without the secret key.
2. The **hash chain** detects changes to history even by someone who also has the key.
3. **Reconciliation** detects a balance that doesn't match its history.
4. **Atomic writes** mean a crash can't leave a half-written file.
5. **Fail secure:** on any integrity failure the app stops instead of running on untrusted data.

### Design decisions

- **No Java serialization.** `ObjectInputStream` is a well-known source of remote code execution bugs, so data is stored as simple delimited text and every field is validated on load.
- **No external libraries** in the application itself. Everything uses the JDK, which reduces supply-chain risk. JUnit is used only for tests.
- **Authorization in the service layer**, not the UI, so no caller can skip it.
- **Trust on first use for the HMAC key** is a documented trade-off for a demo that is shared through a public repository. A production system would keep the key in a keystore or hardware security module.

## Architecture

```
src/main/java/securebank/
├── App.java              Entry point: opens and verifies data, connects the objects
├── model/                User, Account, Transaction (record), TransactionType, Money
├── security/             PasswordHasher, PasswordPolicy, LoginThrottler, Session,
│                         InputValidator, IntegrityService, AccountNumberGenerator, AuditLogger
├── repository/           UserRepository, AccountRepository, TransactionRepository
│                         (interfaces) + in-memory implementations for tests
├── storage/              File-backed repositories, signed files, hash chain,
│                         atomic writes, data folder lock, ledger verifier
├── service/              AuthService, AccountService (all business and security rules)
├── exception/            BankException and its subclasses
└── ui/                   ConsoleMenu (input and output only)
```

**OOP principles applied**

- **Encapsulation:** `Account` has no balance setter. Only `deposit()` and `withdraw()` change it, and they keep it from ever going negative.
- **Immutability:** `Transaction` is a record; `PasswordHash` makes defensive copies of its arrays.
- **Abstraction and polymorphism:** services depend on repository interfaces. Switching from memory to files changed no business logic.
- **Single responsibility:** the UI reads and prints, services enforce rules, repositories store data.
- **Dependency injection:** objects receive what they need through constructors. Tests use this to swap in a controllable clock and fast hashing.
- **Custom exception hierarchy:** every user-facing error is a `BankException` whose message is safe to display.

## Data Files

| File | Contents |
|---|---|
| `data/users.txt` | `username \| PBKDF2 hash \| created \| failed attempts \| locked until` |
| `data/accounts.txt` | `account number \| owner \| balance \| created` |
| `data/transactions.txt` | `id \| account \| type \| amount \| balance after \| time \| previous hash \| hash` |
| `data/.secret.key` | HMAC key, created on first run, **git-ignored** |
| `logs/audit.log` | Security audit trail, **git-ignored** |

Each data file ends with a `#hmac=` line. Editing any file by hand will make the app refuse to start, which is the intended behaviour.

## Limitations

- File permissions are restricted on Linux and macOS. Windows uses its default folder permissions.
- One user at a time per data folder; this is a single-user console application by design.
- The HMAC key sits on the same disk as the data. This protects against casual edits and file copying, not against an attacker with full control of the machine.
