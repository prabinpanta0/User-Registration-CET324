document.addEventListener('DOMContentLoaded', function() {
  const usernameEl = document.getElementById('username');
  const emailEl = document.getElementById('email');
  const lastLoginEl = document.getElementById('lastLogin');
  const mfaStatusEl = document.getElementById('mfaStatus');
  const sessionListEl = document.getElementById('sessionList');
  const logoutBtn = document.getElementById('logoutBtn');

  // MFA Recovery Code Section Elements
  const mfaRecoverySection = document.getElementById('mfaRecoverySection');
  const recoveryCodesStatusEl = document.getElementById('recoveryCodesStatus');
  const regenerateRecoveryCodesBtn = document.getElementById('regenerateRecoveryCodesBtn');
  const newRecoveryCodesDisplay = document.getElementById('newRecoveryCodesDisplay');
  const newRecoveryCodeListEl = document.getElementById('newRecoveryCodeList');
  const copyNewRecoveryCodesBtn = document.getElementById('copyNewRecoveryCodesBtn');
  const downloadNewRecoveryCodesBtn = document.getElementById('downloadNewRecoveryCodesBtn');
  const closeNewRecoveryCodesBtn = document.getElementById('closeNewRecoveryCodesBtn');
  let currentNewRecoveryCodes = []; // To store codes for copy/download

  function logout() {
    // Get CSRF token for logout
    fetch('/csrf-token', { credentials: 'include' })
      .then(response => response.json())
      .then(data => {
        return fetch('/logout', {
          method: 'POST',
          credentials: 'include',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            csrf_token: data.csrf_token
          })
        });
      })
      .then(() => {
        window.location = '/login';
      })
      .catch(err => {
        console.error("Logout failed:", err);
        // Even if logout fails, redirect to login page
        window.location = '/login';
      });
  }

  if (logoutBtn) {
    logoutBtn.addEventListener('click', logout);
  }

  // Fetch user info
  fetch('/dashboard/info', {credentials: 'include'})
    .then(r => {
      if (r.ok) {
        return r.json();
      } else {
        window.location = '/login'; // Redirect if not authenticated
        throw new Error('Not authenticated');
      }
    })
    .then(data => {
      if (usernameEl) usernameEl.textContent = data.username || 'N/A';
      if (emailEl) emailEl.textContent = data.email || 'N/A';
      if (lastLoginEl) lastLoginEl.textContent = data.last_login || 'N/A';
      if (mfaStatusEl) mfaStatusEl.textContent = data.mfa_enabled ? 'Yes' : 'No';

      if (data.mfa_enabled && mfaRecoverySection) {
        mfaRecoverySection.classList.remove('hidden');
        fetchRecoveryCodeStatus();
      }
    })
    .catch(err => {
      console.error('Failed to load user info:', err);
      if (usernameEl) usernameEl.textContent = 'Error loading';
      if (emailEl) emailEl.textContent = 'Error loading';
      if (lastLoginEl) lastLoginEl.textContent = 'Error loading';
      if (mfaStatusEl) mfaStatusEl.textContent = 'Error loading';
    });

  // Load active sessions
  function loadSessions() {
    if (!sessionListEl) return;

    fetch('/dashboard/sessions', {credentials: 'include'})
      .then(r => {
        if (!r.ok) {
          throw new Error('Failed to load sessions: ' + r.status);
        }
        return r.json();
      })
      .then(sessions => {
        sessionListEl.innerHTML = ''; // Clear previous list

        if (sessions.length === 0) {
          const listItem = document.createElement('li');
          listItem.className = 'text-gray-600';
          listItem.textContent = 'No active sessions';
          sessionListEl.appendChild(listItem);
          return;
        }

        sessions.forEach(session => {
          const listItem = document.createElement('li');
          listItem.className = 'flex justify-between items-center py-1';

          const sessionInfoSpan = document.createElement('span');
          sessionInfoSpan.className = 'text-gray-800';
          sessionInfoSpan.textContent = `${session.ip} - ${session.created}`;

          if (session.current) {
            const currentTagSpan = document.createElement('span');
            currentTagSpan.className = 'text-green-600 text-xs ml-1';
            currentTagSpan.textContent = '(Current)';
            sessionInfoSpan.appendChild(currentTagSpan);
          }
          listItem.appendChild(sessionInfoSpan);

          if (session.current) {
            const useLogoutSpan = document.createElement('span');
            useLogoutSpan.className = 'text-gray-400 text-xs';
            useLogoutSpan.textContent = 'Use Logout';
            listItem.appendChild(useLogoutSpan);
          } else {
            const revokeButton = document.createElement('button');
            revokeButton.className = 'text-red-600 hover:text-red-800 text-xs revoke-session-btn';
            revokeButton.textContent = 'Revoke';
            revokeButton.dataset.sessionId = session.id; // Store session ID on the button
            listItem.appendChild(revokeButton);
          }
          sessionListEl.appendChild(listItem);
        });
      })
      .catch(err => {
        console.error('Failed to load sessions:', err);
        sessionListEl.innerHTML = '';
        const listItem = document.createElement('li');
        listItem.className = 'text-red-600';
        listItem.textContent = 'Failed to load sessions';
        sessionListEl.appendChild(listItem);
      });
  }

  function revokeSession(sessionId) {
    // Get CSRF token first, then make the request
    fetch('/csrf-token', {credentials: 'include'})
      .then(r => r.text())
      .then(csrfToken => {
        return fetch(`/dashboard/sessions/${sessionId}/revoke`, {
          method: 'POST',
          headers: {
            'X-CSRF-Token': csrfToken
          },
          credentials: 'include'
        });
      })
      .then(r => {
        if (!r.ok) {
          throw new Error('Failed to revoke session: ' + r.status);
        }
        return r.text();
      })
      .then(() => {
        loadSessions(); // Reload the list
    })
    .catch(err => {
      console.error('Failed to revoke session:', err);
      if (typeof Toastify === 'function') {
        Toastify({ 
          text: 'Failed to revoke session', 
          duration: 3000, 
          style: {
            background: "white",
            color: "black",
            border: "1px solid #ccc"
          }
        }).showToast();
      } else {
        alert('Failed to revoke session');
      }
    });
  }

  // Event delegation for revoke buttons
  if (sessionListEl) {
    sessionListEl.addEventListener('click', function(event) {
      if (event.target && event.target.classList.contains('revoke-session-btn')) {
        const sessionId = event.target.dataset.sessionId;
        if (sessionId) {
          revokeSession(sessionId);
        }
      }
    });
  }

  // Load sessions on page load
  loadSessions();

  function fetchRecoveryCodeStatus() {
    if (!recoveryCodesStatusEl) return;
    fetch('/mfa/recovery-codes/status', {credentials: 'include'})
      .then(r => {
        if (!r.ok) throw new Error('Failed to fetch recovery code status');
        return r.json();
      })
      .then(data => {
        if (data.mfa_enabled) {
          if (data.has_codes) {
            recoveryCodesStatusEl.textContent = `You have ${data.count} recovery code(s) remaining.`;
          } else {
            recoveryCodesStatusEl.textContent = 'You have no recovery codes remaining. Regenerate them if you lose access to your primary MFA method.';
          }
          if (mfaRecoverySection) mfaRecoverySection.classList.remove('hidden');
        } else {
          // Should not happen if this is called after checking mfa_enabled from /dashboard/info
          recoveryCodesStatusEl.textContent = 'MFA is not enabled.';
           if (mfaRecoverySection) mfaRecoverySection.classList.add('hidden');
        }
      })
      .catch(err => {
        console.error(err);
        recoveryCodesStatusEl.textContent = 'Could not load recovery code status.';
      });
  }

  if (regenerateRecoveryCodesBtn) {
    regenerateRecoveryCodesBtn.addEventListener('click', function() {
      if (!confirm("Are you sure you want to regenerate recovery codes? This will invalidate all your old codes.")) {
        return;
      }
      // Fetch CSRF token first, then make the POST request
      fetch('/csrf-token', {credentials: 'include'})
        .then(r => r.text())
        .then(csrfToken => {
          return fetch('/mfa/recovery-codes/regenerate', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-CSRF-Token': csrfToken // Send CSRF token in header
            },
            credentials: 'include'
            // No body needed for this request as per current backend implementation
          });
        })
        .then(r => {
          if (!r.ok) {
            r.text().then(text => { throw new Error('Failed to regenerate codes: ' + text); });
          }
          return r.json();
        })
        .then(data => {
          if (data.status === 'success' && data.recovery_codes) {
            currentNewRecoveryCodes = data.recovery_codes; // Store for copy/download
            if (newRecoveryCodeListEl && newRecoveryCodesDisplay) {
              newRecoveryCodeListEl.innerHTML = '';
              currentNewRecoveryCodes.forEach(code => {
                const li = document.createElement('li');
                li.className = 'p-1 bg-gray-50 border rounded font-mono text-sm text-center';
                li.textContent = code;
                newRecoveryCodeListEl.appendChild(li);
              });
              newRecoveryCodesDisplay.classList.remove('hidden');
            }
            fetchRecoveryCodeStatus(); // Refresh the count
            if (typeof Toastify === 'function') {
              Toastify({ text: 'New recovery codes generated!', duration: 3000 }).showToast();
            } else {
              alert('New recovery codes generated! Save them securely.');
            }
          } else {
            throw new Error(data.message || 'Unknown error during regeneration.');
          }
        })
        .catch(err => {
          console.error('Error regenerating recovery codes:', err);
          if (typeof Toastify === 'function') {
            Toastify({ 
              text: 'Error: ' + err.message, 
              duration: 3000, 
              style: {
                background: "white",
                color: "black",
                border: "1px solid #ccc"
              }
            }).showToast();
          } else {
            alert('Error: ' + err.message);
          }
        });
    });
  }

  if (copyNewRecoveryCodesBtn) {
    copyNewRecoveryCodesBtn.addEventListener('click', function() {
      if (currentNewRecoveryCodes.length > 0) {
        const codesText = currentNewRecoveryCodes.join('\n');
        navigator.clipboard.writeText(codesText).then(() => {
          if (typeof Toastify === 'function') Toastify({ text: 'Codes copied to clipboard!', duration: 2000 }).showToast();
          else alert('Codes copied!');
        }).catch(err => {
          console.error('Failed to copy new codes:', err);
          if (typeof Toastify === 'function') Toastify({ 
            text: 'Failed to copy.', 
            duration: 2000, 
            style: {
              background: "white",
              color: "black",
              border: "1px solid #ccc"
            }
          }).showToast();
          else alert('Failed to copy.');
        });
      }
    });
  }

  if (downloadNewRecoveryCodesBtn) {
    downloadNewRecoveryCodesBtn.addEventListener('click', function() {
      if (currentNewRecoveryCodes.length > 0) {
        const codesText = "Your New MFA Recovery Codes for SecureApp:\n\n" + currentNewRecoveryCodes.join('\n') + "\n\nSave these codes in a secure place. Each code can only be used once. Old codes are now invalid.";
        const blob = new Blob([codesText], { type: 'text/plain;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'secureapp-new-recovery-codes.txt';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      }
    });
  }

  if (closeNewRecoveryCodesBtn) {
    closeNewRecoveryCodesBtn.addEventListener('click', function() {
      if (newRecoveryCodesDisplay) newRecoveryCodesDisplay.classList.add('hidden');
      currentNewRecoveryCodes = []; // Clear codes after closing
    });
  }

});
