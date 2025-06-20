document.addEventListener('DOMContentLoaded', function() {
  const mfaSecretInput = document.getElementById('mfaSecret');
  const qrContainer = document.getElementById('qrContainer');
  const csrfTokenInput = document.getElementById('csrfTokenInput');
  const verifyMfaForm = document.getElementById('verifyMfaForm');

  // Fetch MFA setup data
  if (mfaSecretInput && qrContainer) {
    // Create abort controller for request timeout
    const abortController = new AbortController();
    const timeoutId = setTimeout(() => abortController.abort(), 10000); // 10 second timeout
    
    // First fetch CSRF token, then make MFA setup request
    fetch('/csrf-token', {
      method: 'GET',
      credentials: 'include',
      signal: abortController.signal
    })
    .then(response => {
      clearTimeout(timeoutId);
      if (!response.ok) {
        throw new Error('Failed to fetch CSRF token: ' + response.status);
      }
      return response.json();
    })
    .then(csrfData => {
      const csrfToken = csrfData.csrf_token;
      
      // Create new abort controller for MFA request
      const mfaAbortController = new AbortController();
      const mfaTimeoutId = setTimeout(() => mfaAbortController.abort(), 15000); // 15 second timeout
      
      // Now make the MFA setup request with CSRF token
      return fetch('/mfa/setup', {
        method: 'POST', 
        credentials: 'include',
        signal: mfaAbortController.signal,
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          csrf_token: csrfToken
        })
      }).finally(() => clearTimeout(mfaTimeoutId));
    })
    .then(r => {
      if (!r.ok) {
        throw new Error('Failed to fetch MFA setup data: ' + r.status);
      }
      return r.json();
    })
    .then(data => {
      mfaSecretInput.value = data.secret;
      if (typeof QRCode !== 'undefined') {
        new QRCode(qrContainer, {
          text: data.otpauth,
          width: 256,
          height: 256
        });
      } else {
        qrContainer.innerHTML = '<p class="text-blue-600">QR code library not loaded. Please enter the secret manually in your authenticator app.</p>';
      }
    })
    .catch(err => {
      console.error('Failed to load MFA setup data:', err);
      
      // Determine error type and provide appropriate feedback
      if (err.name === 'AbortError') {
        // Request was aborted (timeout)
        qrContainer.innerHTML = `
          <div class="text-red-500 p-4 border border-red-300 rounded">
            <h3 class="font-bold">Request Timeout</h3>
            <p>The server is taking too long to respond. Please try again.</p>
            <button onclick="window.location.reload()" class="mt-2 px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600">
              Retry
            </button>
          </div>
        `;
      } else if (err.message.includes('Failed to fetch')) {
        // Network error - server might be down
        qrContainer.innerHTML = `
          <div class="text-red-500 p-4 border border-red-300 rounded">
            <h3 class="font-bold">Connection Error</h3>
            <p>Unable to connect to the server. Please check your connection and try again later.</p>
            <button onclick="window.location.reload()" class="mt-2 px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600">
              Retry
            </button>
          </div>
        `;
      } else if (err.message.includes('401')) {
        // Authentication error
        qrContainer.innerHTML = `
          <div class="text-red-500 p-4 border border-red-300 rounded">
            <h3 class="font-bold">Authentication Required</h3>
            <p>Please log in to set up MFA.</p>
            <button onclick="window.location.href='/'" class="mt-2 px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600">
              Go to Login
            </button>
          </div>
        `;
      } else if (err.message.includes('403')) {
        // CSRF or permission error
        qrContainer.innerHTML = `
          <div class="text-red-500 p-4 border border-red-300 rounded">
            <h3 class="font-bold">Security Error</h3>
            <p>Security validation failed. Please refresh the page and try again.</p>
            <button onclick="window.location.reload()" class="mt-2 px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600">
              Refresh Page
            </button>
          </div>
        `;
      } else {
        // Generic error
        qrContainer.innerHTML = `
          <div class="text-red-500 p-4 border border-red-300 rounded">
            <h3 class="font-bold">Error</h3>
            <p>Failed to load MFA setup. Please try again.</p>
            <button onclick="window.location.reload()" class="mt-2 px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600">
              Retry
            </button>
          </div>
        `;
      }
      });
  } else {
    console.warn('MFA secret input or QR container not found.');
  }

  // Fetch CSRF token
  if (csrfTokenInput) {
    fetch('/csrf-token').then(r => r.text()).then(token => {
      csrfTokenInput.value = token;
    }).catch(err => {
      console.warn('Could not fetch CSRF token:', err);
    });
  } else {
    console.warn('CSRF token input not found in MFA setup page.');
  }


  // Handle MFA verification form submission
  if (verifyMfaForm) {
    verifyMfaForm.addEventListener('submit', function(e) {
      e.preventDefault();
      const formData = new FormData(this);
      const data = {};
      formData.forEach((v, k) => data[k] = v);

      const submitBtn = this.querySelector('button[type="submit"]');
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = 'Verifying...';
      }

      // Get CSRF token from the form input
      const csrfToken = document.getElementById('csrfTokenInput')?.value || '';

      fetch('/mfa/verify', {
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
          submitBtn.textContent = 'Verify & Enable MFA';
        }

        if (r.ok) {
          const responseData = await r.json();
          if (responseData.status === 'mfa_enabled' && responseData.recovery_codes && Array.isArray(responseData.recovery_codes)) {
            // Hide the MFA form, show recovery codes section
            if (verifyMfaForm) verifyMfaForm.classList.add('hidden'); // Hide the form itself or its parent container

            const mfaSetupDiv = document.getElementById('mfaSetup'); // Assuming this is the main container for initial setup UI
            if(mfaSetupDiv) mfaSetupDiv.classList.add('hidden');


            const recoveryCodesSection = document.getElementById('recoveryCodesSection');
            const recoveryCodeListEl = document.getElementById('recoveryCodeList');
            const copyCodesBtn = document.getElementById('copyRecoveryCodesBtn');
            const downloadCodesBtn = document.getElementById('downloadRecoveryCodesBtn');
            const proceedBtn = document.getElementById('proceedToDashboardBtn');

            if (recoveryCodesSection && recoveryCodeListEl && copyCodesBtn && downloadCodesBtn && proceedBtn) {
              recoveryCodeListEl.innerHTML = ''; // Clear any previous content
              responseData.recovery_codes.forEach(code => {
                const li = document.createElement('li');
                li.className = 'p-2 bg-gray-100 border rounded font-mono text-center'; // Added some styling
                li.textContent = code;
                recoveryCodeListEl.appendChild(li);
              });

              recoveryCodesSection.classList.remove('hidden');

              copyCodesBtn.addEventListener('click', function() {
                const codesText = responseData.recovery_codes.join('\n');
                navigator.clipboard.writeText(codesText).then(() => {
                  if (typeof Toastify === 'function') {
                    Toastify({ text: 'Recovery codes copied to clipboard!', duration: 2000 }).showToast();
                  } else {
                    alert('Recovery codes copied to clipboard!');
                  }
                }).catch(err => {
                  console.error('Failed to copy recovery codes: ', err);
                  if (typeof Toastify === 'function') {
                    Toastify({ 
                      text: 'Failed to copy codes.', 
                      duration: 2000, 
                      style: {
                        background: "white",
                        color: "black",
                        border: "1px solid #ccc"
                      }
                    }).showToast();
                  } else {
                    alert('Failed to copy codes.');
                  }
                });
              });

              downloadCodesBtn.addEventListener('click', function() {
                const codesText = "Your MFA Recovery Codes for SecureApp:\n\n" + responseData.recovery_codes.join('\n') + "\n\nSave these codes in a secure place. Each code can only be used once.";
                const blob = new Blob([codesText], { type: 'text/plain;charset=utf-8' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'secureapp-recovery-codes.txt';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
              });

              proceedBtn.addEventListener('click', function() {
                window.location = '/dashboard';
              });

            } else {
              console.error('Recovery code display elements not found.');
              window.location = '/dashboard'; // Fallback to redirect if UI elements are missing
            }
          } else {
            // MFA enabled but no recovery codes? Or other unexpected success response.
            console.warn("MFA enabled, but recovery codes not found in response or response format unexpected.", responseData);
            window.location = '/dashboard'; // Fallback
          }
        } else {
          const msg = await r.text();
          // Assuming Toastify might be available via layout.lp
          if (typeof Toastify === 'function') {
            Toastify({ 
              text: 'Error: ' + msg, 
              duration: 3000, 
              style: {
                background: "white",
                color: "black",
                border: "1px solid #ccc"
              }
            }).showToast();
          } else {
            alert('Error: ' + msg);
          }
          const codeInput = this.querySelector('input[name="code"]');
          if (codeInput) {
            codeInput.value = '';
          }
        }
      }).catch(err => {
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.textContent = 'Verify & Enable MFA';
        }
        if (typeof Toastify === 'function') {
           Toastify({ 
             text: 'Network error. Please try again.', 
             duration: 3000, 
             style: {
               background: "white",
               color: "black",
               border: "1px solid #ccc"
             }
           }).showToast();
        } else {
          alert('Network error. Please try again.');
        }
        console.error('MFA verification error:', err);
      });
    });
  } else {
    console.warn('MFA verification form not found.');
  }
});
