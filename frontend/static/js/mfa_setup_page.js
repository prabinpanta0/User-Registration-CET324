document.addEventListener('DOMContentLoaded', function() {
  const mfaSecretInput = document.getElementById('mfaSecret');
  const qrContainer = document.getElementById('qrContainer');
  const csrfTokenInput = document.getElementById('csrfTokenInput');
  const verifyMfaForm = document.getElementById('verifyMfaForm');

  // Fetch MFA setup data
  if (mfaSecretInput && qrContainer) {
    fetch('/mfa/setup', {method: 'POST', credentials: 'include'})
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
        qrContainer.innerHTML = '<p class="text-red-500">Failed to load MFA setup. Please refresh and try again.</p>';
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

      fetch('/mfa/verify', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
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
                    Toastify({ text: 'Failed to copy codes.', duration: 2000, backgroundColor: "linear-gradient(to right, #ff5f6d, #ffc371)" }).showToast();
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
            Toastify({ text: 'Error: ' + msg, duration: 3000, backgroundColor: "linear-gradient(to right, #ff5f6d, #ffc371)" }).showToast();
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
           Toastify({ text: 'Network error. Please try again.', duration: 3000, backgroundColor: "linear-gradient(to right, #ff5f6d, #ffc371)" }).showToast();
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
