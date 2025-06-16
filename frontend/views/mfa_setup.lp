<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MFA Setup - My Lapis App</title>
  <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head>
<body class="bg-gray-100 font-sans leading-normal tracking-normal">
  <div class="container mx-auto p-4">
    <div class="max-w-md mx-auto mt-10 bg-white p-8 rounded shadow">
  <h2 class="text-2xl font-bold mb-6 text-center">Set Up Multi-Factor Authentication</h2>
  <p class="text-gray-600 mb-6 text-center">To complete your registration and secure your account, please set up two-factor authentication.</p>
  <div id="mfaSetup">
    <div class="mb-4">
      <label class="block mb-1 font-semibold text-gray-700">Scan QR Code with Authenticator App</label>
      <div id="qrContainer" class="flex justify-center bg-white p-4 border border-gray-300 rounded-md"></div>
      <p class="text-sm text-gray-600 mt-2">Use apps like Google Authenticator, Authy, or Microsoft Authenticator</p>
    </div>
    <div class="mb-4">
      <label class="block mb-1 font-semibold text-gray-700">Or enter this secret manually:</label>
      <input id="mfaSecret" type="text" class="w-full px-3 py-2 border border-gray-300 rounded-md bg-gray-50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent" readonly />
    </div>
    <form id="verifyMfaForm" method="POST" action="/mfa/verify" autocomplete="off">
      <div class="mb-4">
        <label class="block mb-1 font-semibold text-gray-700">Enter code from your app</label>
        <input name="code" type="text" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-center text-lg tracking-widest" maxlength="6" placeholder="000000" required />
        <p class="text-sm text-gray-600 mt-1">Enter the 6-digit code from your authenticator app</p>
      </div>
      <input type="hidden" name="csrf_token" id="csrfTokenInput" />
      <button type="submit" class="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition duration-200">Verify & Enable MFA</button>
    </form>
  </div>
</div>
<script src="/static/qrcode.min.js"></script>
<script>
// Fetch MFA setup data and CSRF token
fetch('/mfa/setup', {method: 'POST', credentials: 'include'}).then(r => r.json()).then(data => {
  document.getElementById('mfaSecret').value = data.secret;
  // Check if QRCode library loaded successfully
  if (typeof QRCode !== 'undefined') {
    new QRCode(document.getElementById('qrContainer'), {
      text: data.otpauth,
      width: 128,
      height: 128
    });
  } else {
    // Fallback: show manual entry
    document.getElementById('qrContainer').innerHTML = '<p class="text-blue-600">QR code library not loaded. Please enter the secret manually in your authenticator app.</p>';
  }
}).catch(err => {
  console.error('Failed to load MFA setup data:', err);
  document.getElementById('qrContainer').innerHTML = '<p class="text-red-500">Failed to load MFA setup. Please refresh and try again.</p>';
});

fetch('/csrf-token').then(r => r.text()).then(token => {
  document.getElementById('csrfTokenInput').value = token;
}).catch(err => {
  console.warn('Could not fetch CSRF token:', err);
});

// Handle MFA verification form submission
document.getElementById('verifyMfaForm').addEventListener('submit', function(e) {
  e.preventDefault();
  const formData = new FormData(this);
  const data = {};
  formData.forEach((v, k) => data[k] = v);
  
  const submitBtn = this.querySelector('button[type="submit"]');
  submitBtn.disabled = true;
  submitBtn.textContent = 'Verifying...';
  
  fetch('/mfa/verify', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    credentials: 'include',
    body: JSON.stringify(data)
  }).then(async r => {
    submitBtn.disabled = false;
    submitBtn.textContent = 'Verify & Enable MFA';
    
    if (r.ok) {
      // MFA setup successful, redirect to dashboard
      window.location = '/dashboard';
    } else {
      const msg = await r.text();
      alert('Error: ' + msg);
      // Clear the code input on error
      this.querySelector('input[name="code"]').value = '';
    }
  }).catch(err => {
    submitBtn.disabled = false;
    submitBtn.textContent = 'Verify & Enable MFA';
    alert('Network error. Please try again.');
    console.error('MFA verification error:', err);
  });
});
</script>
  </div>
</body>
</html>
