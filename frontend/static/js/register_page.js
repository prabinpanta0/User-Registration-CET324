document.addEventListener('DOMContentLoaded', function() {
  // Get reCAPTCHA site key from body data attribute
  window.RECAPTCHA_SITE_KEY = document.body.getAttribute('data-recaptcha-site-key');
  
  // Fetch CSRF token
  fetch('/csrf-token').then(r => r.json()).then(data => {
    const csrfInput = document.getElementById('csrfTokenInput');
    if (csrfInput && data.csrf_token) {
      csrfInput.value = data.csrf_token;
    }
  }).catch(err => {
    console.warn('Could not fetch CSRF token:', err);
  });

  // Handle registration form submission
  const registerForm = document.getElementById('registerForm');
  if (registerForm) {
    registerForm.addEventListener('submit', function(e) {
      e.preventDefault();
      const formData = new FormData(registerForm);
      const data = {};
      formData.forEach((v, k) => data[k] = v);

      const submitBtn = document.getElementById('submitBtn');
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = 'Registering...';
      }

      // Get CSRF token from the form input - ensure it's just the token value
      const csrfInput = document.getElementById('csrfTokenInput');
      const csrfToken = csrfInput?.value || '';
      
      // Make sure CSRF token is properly set in the data object
      data.csrf_token = csrfToken;
      
      
      fetch('/register', {
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
          submitBtn.textContent = 'Register';
        }

        if (r.ok) {
          // Successful registration - redirect to email verification page
          if (typeof Toastify === 'function') {
            Toastify({
              text: "Registration successful! Redirecting to email verification...",
              duration: 3000,
              close: true,
              gravity: "top",
              position: "center",
              style: {
                background: "white",
                color: "black",
                border: "1px solid #ccc"
              },
              stopOnFocus: true,
            }).showToast();
          }
          
          // Reset form and captcha
          registerForm.reset();
          if (typeof hcaptcha !== 'undefined') {
            try {
              hcaptcha.reset();
            } catch (hcError) {
              console.warn("Error trying to reset hCaptcha:", hcError);
            }
          }
          
          // Redirect to email verification page after a short delay
          setTimeout(() => {
            window.location.href = '/email-verification';
          }, 1500);
        } else {
          const msg = await r.text();
          console.error('Registration failed:', {
            status: r.status,
            statusText: r.statusText,
            response: msg,
            url: r.url
          });
          if (typeof Toastify === 'function') {
            Toastify({
              text: "Registration failed. Please try again.",
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
            alert(msg || "Registration failed. Please try again.");
          }
          // Reset hCaptcha widget if hcaptcha object is available
          if (typeof hcaptcha !== 'undefined') {
             try {
              hcaptcha.reset();
            } catch (hcError) {
              console.warn("Error trying to reset hCaptcha:", hcError);
            }
          }
        }
      }).catch(err => {
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.textContent = 'Register';
        }
        console.error('Registration network error:', {
          error: err,
          message: err.message,
          stack: err.stack
        });
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
        console.error('Registration fetch error:', err);
         // Reset hCaptcha widget if hcaptcha object is available
        if (typeof hcaptcha !== 'undefined') {
            try {
              hcaptcha.reset();
            } catch (hcError) {
              console.warn("Error trying to reset hCaptcha:", hcError);
            }
          }
      });
    });
  } else {
    console.warn('Registration form not found.');
  }
});
