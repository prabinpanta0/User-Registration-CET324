document.addEventListener('DOMContentLoaded', function() {
  const urlParams = new URLSearchParams(window.location.search);
  const statusDiv = document.getElementById('verification-status');
  const verificationForm = document.getElementById('verification-form');
  const form = document.getElementById('verifyEmailForm');
  const codeInput = document.getElementById('codeInput');
  const csrfTokenInput = document.getElementById('csrfTokenInput');
  
  // Get CSRF token
  fetch('/csrf-token', {
    method: 'GET',
    credentials: 'include'
  }).then(response => response.json())
    .then(data => {
      if (data.csrf_token) {
        csrfTokenInput.value = data.csrf_token;
      }
    })
    .catch(err => console.warn('Failed to fetch CSRF token:', err));
  
  // Check if there's a token in the URL for automatic verification
  const token = urlParams.get('token');
  
  if (token) {
    // Automatic verification via JWT token
    fetch('/verify-email?token=' + encodeURIComponent(token), {
      method: 'GET',
      credentials: 'include'
    }).then(async response => {
      const responseText = await response.text();
      
      if (response.ok) {
        try {
          // Try to parse as JSON first
          const responseData = JSON.parse(responseText);
          if (responseData.status === 'verified' && responseData.redirect) {
            // Success - email verified, redirect to MFA setup
            showSuccessMessage();
            setTimeout(() => {
              window.location.href = responseData.redirect;
            }, 2000);
          } else if (responseData.status === 'already_verified' && responseData.redirect) {
            // Already verified, redirect to login
            showAlreadyVerifiedMessage();
            setTimeout(() => {
              window.location.href = responseData.redirect;
            }, 2000);
          } else {
            // Fallback for unexpected success response
            showSuccessMessage();
            setTimeout(() => {
              window.location.href = '/mfa/setup';
            }, 2000);
          }
        } catch (jsonError) {
          // Fallback for non-JSON response
          if (responseText.includes('already verified')) {
            showAlreadyVerifiedMessage();
            setTimeout(() => {
              window.location.href = '/login';
            }, 2000);
          } else {
            showSuccessMessage();
            setTimeout(() => {
              window.location.href = '/mfa/setup';
            }, 2000);
          }
        }
      } else {
        // Error during verification
        let errorMessage = responseText || 'Email verification failed.';
        
        if (responseText.includes('already verified')) {
          showAlreadyVerifiedMessage();
        } else {
          showErrorMessage(errorMessage);
        }
        
        showToast(errorMessage);
      }
    }).catch(err => {
      console.error('Verification error:', err);
      showNetworkErrorMessage();
      showToast('Network error. Please try again.');
    });
  } else {
    // No token in URL - show code input form
    statusDiv.style.display = 'none';
    verificationForm.classList.remove('hidden');
  }
  
  // Handle code verification form submission
  if (form) {
    form.addEventListener('submit', async function(e) {
      e.preventDefault();
       const code = codeInput.value.trim();
      if (!code || code.length !== 6) {
        showToast('Please enter a valid 6-digit code');
        return;
      }

      // Send as URL-encoded form data instead of multipart
      const formData = new URLSearchParams();
      formData.append('code', code);
      formData.append('csrf_token', csrfTokenInput.value);

      try {
        const response = await fetch('/verify-email-code', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: formData,
          credentials: 'include'
        });
        
        const responseText = await response.text();
        
        if (response.ok) {
          try {
            // Try to parse as JSON first
            const responseData = JSON.parse(responseText);
            if (responseData.status === 'verified' && responseData.redirect) {
              // Success - email verified, redirect to MFA setup
              verificationForm.style.display = 'none';
              statusDiv.style.display = 'block';
              showSuccessMessage();
              showToast('Email verified successfully!');
              setTimeout(() => {
                window.location.href = responseData.redirect;
              }, 2000);
            } else if (responseData.status === 'already_verified' && responseData.redirect) {
              // Already verified, redirect to login
              verificationForm.style.display = 'none';
              statusDiv.style.display = 'block';
              showAlreadyVerifiedMessage();
              showToast('Email already verified!');
              setTimeout(() => {
                window.location.href = responseData.redirect;
              }, 2000);
            } else {
              // Fallback for unexpected success response
              verificationForm.style.display = 'none';
              statusDiv.style.display = 'block';
              showSuccessMessage();
              showToast('Email verified successfully!');
              setTimeout(() => {
                window.location.href = '/mfa/setup';
              }, 2000);
            }
          } catch (jsonError) {
            // Fallback for non-JSON response
            verificationForm.style.display = 'none';
            statusDiv.style.display = 'block';
            showSuccessMessage();
            showToast('Email verified successfully!');
            setTimeout(() => {
              window.location.href = '/mfa/setup';
            }, 2000);
          }
        } else {
          showToast(responseText || 'Verification failed. Please check your code.');
        }
      } catch (err) {
        console.error('Code verification error:', err);
        showToast('Network error. Please try again.');
      }
    });
  }
  
  function showSuccessMessage() {
    statusDiv.innerHTML = `
      <div class="text-green-600 mb-4">
        <svg class="mx-auto h-16 w-16 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
        </svg>
        <h2 class="text-2xl font-bold mb-2">Email Verified Successfully!</h2>
        <p class="text-gray-600 mb-4">Your email has been verified. Redirecting to MFA setup...</p>
        <div class="flex justify-center">
          <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-green-600"></div>
        </div>
      </div>
    `;
    
    showToast("Email verified successfully!");
  }
  
  function showAlreadyVerifiedMessage() {
    statusDiv.innerHTML = `
      <div class="text-blue-600 mb-4">
        <svg class="mx-auto h-16 w-16 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
        </svg>
        <h2 class="text-2xl font-bold mb-2">Already Verified</h2>
        <p class="text-gray-600 mb-4">Your email is already verified. You can log in to your account.</p>
        <a href="/login" class="inline-block bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition duration-200">Go to Login</a>
      </div>
    `;
  }
  
  function showErrorMessage(message) {
    statusDiv.innerHTML = `
      <div class="text-red-600 mb-4">
        <svg class="mx-auto h-16 w-16 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16c-.77.833.192 2.5 1.732 2.5z"></path>
        </svg>
        <h2 class="text-2xl font-bold mb-2">Verification Failed</h2>
        <p class="text-gray-600 mb-4">${message}</p>
        <div class="space-x-3">
          <a href="/register" class="inline-block bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition duration-200">Register Again</a>
          <a href="/login" class="inline-block bg-gray-600 text-white py-2 px-4 rounded-md hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-offset-2 transition duration-200">Back to Login</a>
        </div>
      </div>
    `;
  }
  
  function showNetworkErrorMessage() {
    statusDiv.innerHTML = `
      <div class="text-red-600 mb-4">
        <svg class="mx-auto h-16 w-16 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16c-.77.833.192 2.5 1.732 2.5z"></path>
        </svg>
        <h2 class="text-2xl font-bold mb-2">Connection Error</h2>
        <p class="text-gray-600 mb-4">Network error occurred. Please try again later.</p>
        <a href="/register" class="inline-block bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition duration-200">Register Again</a>
      </div>
    `;
  }
  
  function showToast(message) {
    if (typeof Toastify === 'function') {
      Toastify({
        text: message,
        duration: 5000,
        close: true,
        gravity: "top",
        position: "center",
        style: {
          background: "white",
          color: "black",
          border: "1px solid #ccc"
        },
      }).showToast();
    }
  }
});
