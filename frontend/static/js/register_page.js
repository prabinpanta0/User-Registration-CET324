document.addEventListener('DOMContentLoaded', function() {
  // Fetch CSRF token
  fetch('/csrf-token').then(r => r.text()).then(token => {
    const csrfInput = document.getElementById('csrfTokenInput');
    if (csrfInput) {
      csrfInput.value = token;
    } else {
      console.warn('CSRF token input field not found.');
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

      fetch('/register', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        credentials: 'include',
        body: JSON.stringify(data)
      }).then(async r => {
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.textContent = 'Register';
        }

        if (r.ok) {
          // Successful registration
          if (typeof Toastify === 'function') {
            Toastify({
              text: "Registration successful! Please check your email to verify.",
              duration: 5000,
              close: true,
              gravity: "top",
              position: "center",
              backgroundColor: "linear-gradient(to right, #00b09b, #96c93d)",
              stopOnFocus: true,
            }).showToast();
          } else {
            alert("Registration successful! Please check your email to verify.");
          }
          registerForm.reset();
          // Reset hCaptcha widget if hcaptcha object is available
          if (typeof hcaptcha !== 'undefined') {
            try {
              hcaptcha.reset();
            } catch (hcError) {
              console.warn("Error trying to reset hCaptcha:", hcError);
            }
          }
        } else {
          const msg = await r.text();
          if (typeof Toastify === 'function') {
            Toastify({
              text: msg || "Registration failed. Please try again.",
              duration: 3000,
              close: true,
              gravity: "top",
              position: "right",
              backgroundColor: "linear-gradient(to right, #ff5f6d, #ffc371)",
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
