document.addEventListener('DOMContentLoaded', function() {
  // Get reCAPTCHA site key from global variable or body data attribute as fallback
  if (!window.RECAPTCHA_SITE_KEY) {
    window.RECAPTCHA_SITE_KEY = document.body.getAttribute('data-recaptcha-site-key');
  }
  
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

  const captchaImg = document.getElementById('captchaImg');
  const captchaErrorDiv = document.getElementById('captchaError');
  const csrfTokenInput = document.getElementById('csrfTokenInput');
  const mfaCsrfTokenInput = document.getElementById('mfaCsrfTokenInput');
  const submitBtn = document.getElementById('submitBtn'); // Login form submit button

  function refreshCaptcha() {
    if (captchaImg && captchaErrorDiv) {
      captchaImg.classList.remove('hidden');
      captchaErrorDiv.classList.add('hidden');
      captchaImg.src = '/captcha?' + Date.now();
    }
  }

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

  // Fetch CSRF token and set it in both forms (use include for credentials)
  fetch('/csrf-token', {credentials: 'include'})
    .then(r => r.json())
    .then(data => {
      if (csrfTokenInput) csrfTokenInput.value = data.csrf_token;
      if (mfaCsrfTokenInput) mfaCsrfTokenInput.value = data.csrf_token;
    })
    .catch(err => {
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
        style: {
          background: "white",
          color: "black",
          border: "1px solid #ccc"
        },
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
      
      // Check if custom captcha is filled
      const captchaInput = loginForm.querySelector('input[name="captcha"]');
      if (!captchaInput || !captchaInput.value.trim()) {
        if (typeof Toastify === 'function') {
          Toastify({
            text: 'Please enter the captcha code.',
            duration: 3000,
            close: true,
            gravity: "top",
            position: "right",
            style: {
              background: "white",
              color: "black",
              border: "1px solid #ccc"
            },
            stopOnFocus: true,
          }).showToast();
        } else {
          alert('Please enter the captcha code.');
        }
        return;
      }

      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = 'Logging in...';
      }

      // Get reCAPTCHA v3 token
      if (typeof grecaptcha !== 'undefined' && window.RECAPTCHA_SITE_KEY) {
        grecaptcha.ready(function() {
          grecaptcha.execute(window.RECAPTCHA_SITE_KEY, {action: 'login'}).then(function(token) {
            submitLoginForm(token);
          });
        });
      } else {
        console.warn('reCAPTCHA v3 not loaded or site key not available, submitting without token');
        submitLoginForm('');
      }
    });
  }

  function submitLoginForm(recaptchaToken) {
    const formData = new FormData(loginForm);
    const data = {};
    formData.forEach((v, k) => data[k] = v);
    
    // Add reCAPTCHA token
    data.recaptcha_token = recaptchaToken;

    // Get CSRF token from the form input
    const csrfToken = document.getElementById('csrfTokenInput')?.value || '';

    fetch('/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken
      },
      credentials: 'include',
      body: JSON.stringify(data)
    }).then(async r => {
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Login';
      }        if (r.ok) {
          const resultText = await r.text(); // Read as text first
          try {
            const resultJson = JSON.parse(resultText); // Try to parse as JSON
            if (resultJson.status === 'mfa_required') {
              showMfaForm();
            } else if (resultJson.status === 'success' || resultJson.status === 'Login successful.') {
              // Handle redirect based on response
              const redirectUrl = resultJson.redirect || '/dashboard';
              window.location = redirectUrl;
            } else {
               // Default fallback - check for redirect in response
               const redirectUrl = resultJson.redirect || '/dashboard';
               window.location = redirectUrl;
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
              style: {
                background: "white",
                color: "black",
                border: "1px solid #ccc"
              },
              stopOnFocus: true,
            }).showToast();
          } else {
            alert(msg || 'Login failed. Please try again.');
          }
          // Refresh custom captcha
          refreshCaptcha();
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
            style: {
              background: "white",
              color: "black",
              border: "1px solid #ccc"
            },
            stopOnFocus: true,
          }).showToast();
        } else {
          alert('Network error. Please try again.');
        }
        // Refresh custom captcha
        refreshCaptcha();
        console.error('Login fetch error:', err);
      });
  } // Close submitLoginForm function

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

      // Refresh CSRF token before MFA verification
      fetch('/csrf-token', {credentials: 'include'})
        .then(r => r.json())
        .then(csrfData => {
          // Include new CSRF token in body for JSON extraction or header
          data.csrf_token = csrfData.csrf_token;
          return fetch('/login/mfa', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-CSRF-Token': csrfData.csrf_token
            },
            credentials: 'include',
            body: JSON.stringify(data)
          });
        }).then(async r => {
          const mfaSubmitBtn = mfaVerifyForm.querySelector('button[type="submit"]');
          if (mfaSubmitBtn) {
            mfaSubmitBtn.disabled = false;
            // Text reset depends on whether it's "Verify" or "Verify & Enable MFA"
            mfaSubmitBtn.textContent = 'Verify';
          }
          if (r.ok) {
            const resultText = await r.text();
            try {
              const resultJson = JSON.parse(resultText);
              const redirectUrl = resultJson.redirect || '/dashboard';
              window.location = redirectUrl;
            } catch (jsonError) {
              // Fallback to dashboard if JSON parsing fails but response is OK
              window.location = '/dashboard';
            }
          } else {
            const msg = await r.text();
            if (typeof Toastify === 'function') {
              Toastify({
                text: msg || 'MFA verification failed.',
                duration: 3000,
                close: true,
                gravity: "top",
                position: "right",
                style: {
                  background: "white",
                  color: "black",
                  border: "1px solid #ccc"
                },
                stopOnFocus: true,
              }).showToast();
            } else {
              alert(msg || 'MFA verification failed.');
            }
          }
        }).catch(err => {
          const mfaSubmitBtn = mfaVerifyForm.querySelector('button[type="submit"]');
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
                style: {
                  background: "white",
                  color: "black",
                  border: "1px solid #ccc"
                },
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
