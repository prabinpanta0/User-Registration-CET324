# Frontend Tests

This directory contains test files for the frontend Lua modules and HTML components.

## Test Files

- `test_env_loader.lua` - Tests environment variable loading functionality
- `test_recaptcha.html` - Tests reCAPTCHA v3 integration and loading

## Running Tests

### Lua Tests

To run the Lua tests, you'll need Lua installed and access to the Lapis environment:

```bash
cd /home/idleshade/ASSIGNMENT_ACS/frontend/test
lua test_env_loader.lua
```

### HTML Tests

To test the reCAPTCHA functionality:

1. Start the frontend server
2. Open `test_recaptcha.html` in a browser
3. Click the "Test reCAPTCHA" button to verify that reCAPTCHA v3 loads correctly

## Notes

- Make sure the `.env` file is properly configured in the frontend directory
- reCAPTCHA tests require a valid site key configured in the environment variables
