document.addEventListener('DOMContentLoaded', function() {
  const loginForm = document.getElementById('loginForm');
  const mfaFormContainer = document.getElementById('mfaForm'); // Renamed for clarity
  const mfaVerifyForm = document.getElementById('mfaVerifyForm');
  const mfaFormTitle = document.getElementById('mfaFormTitle');
  const mfaCodeEntry = document.getElementById('mfaCodeEntry');
  const mfaCodeInput = document.getElementById('mfaCodeInput');
  const mfaRecoveryCodeEntry = document.getElementById('mfaRecoveryCodeEntry');
  const mfaRecoveryCodeInput = document.getElementById('mfaRecoveryCodeInput');
  const toggleMfaInputLink = document.getElementById('toggleMfaInputLink');
  let usingRecoveryCode = false;

  const csrfTokenInput = document.getElementById('csrfTokenInput');
  const mfaCsrfTokenInput = document.getElementById('mfaCsrfTokenInput');
  const submitBtn = document.getElementById('submitBtn'); // Login form submit button

  function showMfaForm() {
    if (loginForm && mfaFormContainer) {
    loginForm.classList.add('hidden'); // Assuming loginForm itself should be hidden by class
    // loginForm.style.display = 'none'; // Old way
    mfaFormContainer.classList.remove('hidden');
    }
  }

  function showLoginForm() {
    if (mfaFormContainer && loginForm) {
      mfaFormContainer.classList.add('hidden');
    loginForm.classList.remove('hidden'); // Assuming loginForm should be shown by removing class
    // loginForm.style.display = 'block'; // Old way
    }
  }

  // Attach event listeners
  const backToLoginBtn = document.getElementById('backToLoginBtn');
  if (backToLoginBtn) {
    backToLoginBtn.addEventListener('click', showLoginForm);
  }

  if (toggleMfaInputLink) {
    toggleMfaInputLink.addEventListener('click', function(e) {
      e.preventDefault();
      usingRecoveryCode = !usingRecoveryCode;
      if (usingRecoveryCode) {
        if (mfaCodeEntry) mfaCodeEntry.classList.add('hidden');
        if (mfaRecoveryCodeEntry) mfaRecoveryCodeEntry.classList.remove('hidden');
        if (mfaRecoveryCodeInput) mfaRecoveryCodeInput.required = true; // Make recovery code required
        if (mfaCodeInput) mfaCodeInput.required = false; // Make TOTP code not required
        if (mfaFormTitle) mfaFormTitle.textContent = 'Enter Recovery Code';
        toggleMfaInputLink.textContent = 'Use an authenticator code';
        if (mfaRecoveryCodeInput) mfaRecoveryCodeInput.focus();
      } else {
        if (mfaCodeEntry) mfaCodeEntry.classList.remove('hidden');
        if (mfaRecoveryCodeEntry) mfaRecoveryCodeEntry.classList.add('hidden');
        if (mfaCodeInput) mfaCodeInput.required = true; // Make TOTP code required
        if (mfaRecoveryCodeInput) mfaRecoveryCodeInput.required = false; // Make recovery code not required
        if (mfaFormTitle) mfaFormTitle.textContent = 'Enter MFA Code';
        toggleMfaInputLink.textContent = 'Use a recovery code';
        if (mfaCodeInput) mfaCodeInput.focus();
      }
    });
  }

  // Fetch CSRF token and set it in both forms
  fetch('/csrf-token').then(r => r.text()).then(token => {
    if (csrfTokenInput) csrfTokenInput.value = token;
    if (mfaCsrfTokenInput) mfaCsrfTokenInput.value = token;
  }).catch(err => {
    console.warn('Could not fetch CSRF token:', err);
  });

  // Check for registration success message
  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.get('registered') === 'true') {
    if (typeof Toastify === 'function') {
      Toastify({
        text: 'Registration successful! Please log in with your credentials.',
        duration: 3000,
        close: true,
        gravity: "top",
        position: "right",
        backgroundColor: "linear-gradient(to right, #00b09b, #96c93d)",
        stopOnFocus: true,
      }).showToast();
    } else {
      alert('Registration successful! Please log in with your credentials.');
    }
    window.history.replaceState({}, document.title, window.location.pathname);
  }

  // Handle login form submission with AJAX
  if (loginForm) {
    loginForm.addEventListener('submit', function(e) {
      e.preventDefault();
      
      // Get hCaptcha response
      const hcaptchaResponse = window.hcaptcha ? window.hcaptcha.getResponse() : '';
      if (!hcaptchaResponse) {
        if (typeof Toastify === 'function') {
          Toastify({
            text: 'Please complete the captcha verification.',
            duration: 3000,
            close: true,
            gravity: "top",
            position: "right",
            backgroundColor: "linear-gradient(to right, #ff5f6d, #ffc371)",
            stopOnFocus: true,
          }).showToast();
        } else {
          alert('Please complete the captcha verification.');
        }
        return;
      }
      
      const formData = new FormData(loginForm);
      const data = {};
      formData.forEach((v, k) => data[k] = v);
      
      // Add hCaptcha response
      data['h-captcha-response'] = hcaptchaResponse;

      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = 'Logging in...';
      }

      fetch('/login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        credentials: 'include',
        body: JSON.stringify(data)
      }).then(async r => {
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.textContent = 'Login';
        }

        if (r.ok) {
          const resultText = await r.text(); // Read as text first
          try {
            const resultJson = JSON.parse(resultText); // Try to parse as JSON
            if (resultJson.status === 'mfa_required') {
              showMfaForm();
            } else {
               window.location = '/dashboard'; // Or based on other JSON fields
            }
          } catch (jsonError) {
            // If not JSON, or JSON doesn't match expected structure, assume it's a simple success
            // This part might need adjustment based on actual backend responses for non-MFA success
             if (resultText.includes("Login successful")) { // Fallback check if not JSON
                window.location = '/dashboard';
             } else if (resultText.includes("mfa_required")) { // Check text if JSON parsing failed but text indicates MFA
                showMfaForm();
             } else {
                // Default to dashboard on OK if response is not understood but indicates success generally
                console.warn("Login response OK, but content not as expected:", resultText);
                window.location = '/dashboard';
             }
          }
        } else {
          const msg = await r.text();
          if (typeof Toastify === 'function') {
            Toastify({
              text: msg || 'Login failed. Please try again.',
              duration: 3000,
              close: true,
              gravity: "top",
              position: "right",
              backgroundColor: "linear-gradient(to right, #ff5f6d, #ffc371)",
              stopOnFocus: true,
            }).showToast();
          } else {
            alert(msg || 'Login failed. Please try again.');
          }
          // Reset hCaptcha widget
          if (window.hcaptcha) {
            window.hcaptcha.reset();
          }
        }
      }).catch(err => {
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.textContent = 'Login';
        }
        if (typeof Toastify === 'function') {
          Toastify({
            text: 'Network error. Please try again.',
            duration: 3000,
            close: true,
            gravity: "top",
            position: "right",
            backgroundColor: "linear-gradient(to right, #ff5f6d, #ffc371)",
            stopOnFocus: true,
          }).showToast();
        } else {
          alert('Network error. Please try again.');
        }
        // Reset hCaptcha widget
        if (window.hcaptcha) {
          window.hcaptcha.reset();
        }
        console.error('Login fetch error:', err);
      });
    });
  }

  // Handle MFA form submission
  if (mfaVerifyForm) {
    mfaVerifyForm.addEventListener('submit', function(e) {
      e.preventDefault();
      const formData = new FormData(mfaVerifyForm);
      const data = {};
      // Only include the active input's value
      if (usingRecoveryCode) {
        data.mfa_recovery_code = formData.get('mfa_recovery_code');
      } else {
        data.mfa_code = formData.get('mfa_code');
      }
      // Always include CSRF token
      data.csrf_token = formData.get('csrf_token');

      const mfaSubmitBtn = mfaVerifyForm.querySelector('button[type="submit"]');
      if (mfaSubmitBtn) {
        mfaSubmitBtn.disabled = true;
        mfaSubmitBtn.textContent = 'Verifying...';
      }

      fetch('/login/mfa', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        credentials: 'include',
        body: JSON.stringify(data)
      }).then(async r => {
        if (mfaSubmitBtn) {
          mfaSubmitBtn.disabled = false;
          // Text reset depends on whether it's "Verify" or "Verify & Enable MFA"
          mfaSubmitBtn.textContent = 'Verify';
        }
        if (r.ok) {
          window.location = '/dashboard';
        } else {
          const msg = await r.text();
          if (typeof Toastify === 'function') {
            Toastify({
              text: msg || 'MFA verification failed.',
              duration: 3000,
              close: true,
              gravity: "top",
              position: "right",
              backgroundColor: "linear-gradient(to right, #ff5f6d, #ffc371)",
              stopOnFocus: true,
            }).showToast();
          } else {
            alert(msg || 'MFA verification failed.');
          }
        }
      }).catch(err => {
        if (mfaSubmitBtn) {
          mfaSubmitBtn.disabled = false;
          mfaSubmitBtn.textContent = 'Verify';
        }
         if (typeof Toastify === 'function') {
            Toastify({
              text: 'Network error during MFA. Please try again.',
              duration: 3000,
              close: true,
              gravity: "top",
              position: "right",
              backgroundColor: "linear-gradient(to right, #ff5f6d, #ffc371)",
              stopOnFocus: true,
            }).showToast();
        } else {
          alert('Network error during MFA. Please try again.');
        }
        console.error('MFA fetch error:', err);
      });
    });
  }
});
