# Backend Tests

This directory contains test files for the backend Nim modules.

## Test Files

- `test_db.nim` - Tests database connectivity and operations
- `test_env.nim` - Tests environment variable loading
- `test_crypto.nim` - Tests cryptographic functions
- `test_argon2.nim` - Tests Argon2 password hashing
- `test_cookies.nim` - Tests cookie functionality
- `test_jester.nim` - Tests Jester web framework functionality

## Running Tests

To run the tests, compile and execute each test file:

```bash
cd /home/idleshade/ASSIGNMENT_ACS/backend/test
nim c -r test_db.nim
nim c -r test_env.nim
nim c -r test_crypto.nim
nim c -r test_argon2.nim
nim c -r test_cookies.nim
nim c -r test_jester.nim
```

Make sure the `.env` file is properly configured in the backend directory before running database-related tests.
