<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login - My Lapis App</title>
  <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head>
<body class="bg-gray-100 font-sans leading-normal tracking-normal">
  <div class="container mx-auto p-4">
    <div class="max-w-md mx-auto mt-10 bg-white p-8 rounded shadow">
      <h2 class="text-2xl font-bold mb-6 text-center">Login</h2>
      <div id="successMessage" class="text-green-600 mb-4 hidden"></div>
      <div id="loginError" class="text-red-600 mb-4 hidden"></div>
      
      <!-- Regular Login Form -->
      <form id="loginForm" method="POST" action="/login" autocomplete="off">
        <div class="mb-4">
          <label class="block mb-1 font-semibold text-gray-700">Username or Email</label>
          <input name="username" type="text" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent" required />
        </div>
        <div class="mb-4">
          <label class="block mb-1 font-semibold text-gray-700">Password</label>
          <input name="password" type="password" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent" required />
        </div>
        <div class="mb-4">
          <label class="block mb-1 font-semibold text-gray-700">Captcha</label>
          <div class="flex items-center mb-2">
            <img id="captchaImg" src="/captcha" alt="Captcha" class="h-12 mr-2 border border-gray-300 rounded bg-gray-50" onerror="this.style.display='none'; document.getElementById('captchaError').style.display='block';" />
            <button type="button" onclick="refreshCaptcha()" class="text-sm text-blue-600 hover:text-blue-800 underline">Refresh</button>
          </div>
          <div id="captchaError" class="text-red-500 text-sm mb-2" style="display:none;">Captcha image failed to load. Please refresh the page.</div>
          <input name="captcha" type="text" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent" required maxlength="6" placeholder="Enter captcha code" />
        </div>
        <input type="hidden" name="csrf_token" id="csrfTokenInput" />
        <button id="submitBtn" type="submit" class="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition duration-200">Login</button>
      </form>

      <!-- MFA Form (hidden by default) -->
      <div id="mfaForm" class="hidden">
        <h3 class="text-lg font-semibold mb-4 text-center">Enter MFA Code</h3>
        <form id="mfaVerifyForm" method="POST" action="/login/mfa" autocomplete="off">
          <div class="mb-4">
            <label class="block mb-1 font-semibold text-gray-700">MFA Code</label>
            <input name="mfa_code" type="text" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-center text-lg tracking-widest" maxlength="6" placeholder="000000" required />
            <p class="text-sm text-gray-600 mt-1">Enter the 6-digit code from your authenticator app</p>
          </div>
          <input type="hidden" name="csrf_token" id="mfaCsrfTokenInput" />
          <button type="submit" class="w-full bg-green-600 text-white py-2 px-4 rounded-md hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-green-500 focus:ring-offset-2 transition duration-200">Verify</button>
          <button type="button" onclick="showLoginForm()" class="w-full mt-2 bg-gray-600 text-white py-2 px-4 rounded-md hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-offset-2 transition duration-200">Back to Login</button>
        </form>
      </div>

      <!-- Navigation Links -->
      <div class="mt-6 text-center">
        <p class="text-gray-600">Don't have an account? 
          <a href="/register" class="text-blue-600 hover:text-blue-800 underline font-semibold">Sign up here</a>
        </p>
        <p class="mt-2 text-gray-600">
          <a href="/forgot-password" class="text-sm text-blue-600 hover:text-blue-800 underline">Forgot Password?</a>
        </p>
      </div>
    </div>
  </div>

<script>
function refreshCaptcha() {
  const img = document.getElementById('captchaImg');
  const errorDiv = document.getElementById('captchaError');
  img.style.display = 'block';
  errorDiv.style.display = 'none';
  img.src = '/captcha?' + Date.now();
}

function showMfaForm() {
  document.getElementById('loginForm').style.display = 'none';
  document.getElementById('mfaForm').classList.remove('hidden');
}

function showLoginForm() {
  document.getElementById('mfaForm').classList.add('hidden');
  document.getElementById('loginForm').style.display = 'block';
}

// Fetch CSRF token and set it in both forms
fetch('/csrf-token').then(r => r.text()).then(token => {
  document.getElementById('csrfTokenInput').value = token;
  document.getElementById('mfaCsrfTokenInput').value = token;
}).catch(err => {
  console.warn('Could not fetch CSRF token:', err);
});

// Check for registration success message
const urlParams = new URLSearchParams(window.location.search);
if (urlParams.get('registered') === 'true') {
  const successDiv = document.getElementById('successMessage');
  successDiv.textContent = 'Registration successful! Please log in with your credentials.';
  successDiv.classList.remove('hidden');
  // Remove the parameter from URL
  window.history.replaceState({}, document.title, window.location.pathname);
}

// Handle login form submission with AJAX
const loginForm = document.getElementById('loginForm');
loginForm.addEventListener('submit', function(e) {
  e.preventDefault();
  const formData = new FormData(loginForm);
  const data = {};
  formData.forEach((v, k) => data[k] = v);
  
  const submitBtn = document.getElementById('submitBtn');
  submitBtn.disabled = true;
  submitBtn.textContent = 'Logging in...';
  
  fetch('/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    credentials: 'include',
    body: JSON.stringify(data)
  }).then(async r => {
    submitBtn.disabled = false;
    submitBtn.textContent = 'Login';
    
    if (r.ok) {
      const result = await r.text();
      if (result.includes('mfa_required')) {
        showMfaForm();
      } else {
        window.location = '/dashboard';
      }
    } else {
      const msg = await r.text();
      const errDiv = document.getElementById('loginError');
      errDiv.textContent = msg;
      errDiv.classList.remove('hidden');
      refreshCaptcha();
    }
  }).catch(err => {
    submitBtn.disabled = false;
    submitBtn.textContent = 'Login';
    const errDiv = document.getElementById('loginError');
    errDiv.textContent = 'Network error. Please try again.';
    errDiv.classList.remove('hidden');
  });
});

// Handle MFA form submission
const mfaForm = document.getElementById('mfaVerifyForm');
mfaForm.addEventListener('submit', function(e) {
  e.preventDefault();
  const formData = new FormData(mfaForm);
  const data = {};
  formData.forEach((v, k) => data[k] = v);
  
  fetch('/login/mfa', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    credentials: 'include',
    body: JSON.stringify(data)
  }).then(async r => {
    if (r.ok) {
      window.location = '/dashboard';
    } else {
      const msg = await r.text();
      const errDiv = document.getElementById('loginError');
      errDiv.textContent = msg;
      errDiv.classList.remove('hidden');
    }
  });
});
</script>
</body>
</html>
