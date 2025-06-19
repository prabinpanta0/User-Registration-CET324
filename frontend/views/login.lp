<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login - My Lapis App</title>
  <link rel="icon" type="image/x-icon" href="/favicon.ico">
  <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
  <link rel="stylesheet" href="/static/tailwind.css">
  <script>
    // Set reCAPTCHA site key
    window.RECAPTCHA_SITE_KEY = '<%= recaptcha_site_key %>';
  </script>
  <script src="https://www.google.com/recaptcha/api.js?render=<%= recaptcha_site_key %>"></script>
</head>
<body class="bg-gray-50 font-sans leading-normal tracking-normal" data-recaptcha-site-key="<%= recaptcha_site_key %>"> <!-- bg-gray-100 to bg-gray-50 -->
  <div class="container mx-auto p-4">
    <div class="max-w-md mx-auto mt-16 bg-white p-10 rounded shadow"> <!-- mt-10 to mt-16, p-8 to p-10 -->
      <h2 class="text-3xl font-bold mb-6 text-center">Login</h2> <!-- text-2xl to text-3xl -->
      
      <!-- Regular Login Form -->
      <form id="loginForm" method="POST" action="/login" autocomplete="off">
        <div class="mb-6"> <!-- mb-4 to mb-6 -->
          <label class="block mb-1 font-semibold text-gray-700">Username or Email</label>
          <input name="username" type="text" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent" required />
        </div>
        <div class="mb-6"> <!-- mb-4 to mb-6 -->
          <label class="block mb-1 font-semibold text-gray-700">Password</label>
          <input name="password" type="password" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent" required />
        </div>
        <div class="mb-6"> <!-- mb-4 to mb-6 -->
          <label class="block mb-1 font-semibold text-gray-700">Captcha</label>
          <div class="flex items-center mb-2 gap-x-3">
            <img id="captchaImg" src="/captcha" alt="Captcha" class="h-12 border border-gray-300 rounded bg-gray-50" onerror="this.classList.add('hidden'); document.getElementById('captchaError').classList.remove('hidden');" />
            <button type="button" id="refreshCaptchaBtn" class="text-sm text-blue-600 hover:text-blue-800 underline">Refresh</button>
          </div>
          <div id="captchaError" class="text-red-500 text-sm mb-2 hidden">Captcha image failed to load. Please refresh the page.</div>
          <input name="captcha" type="text" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent" required maxlength="6" placeholder="Enter captcha code" />
        </div>
        <input type="hidden" name="csrf_token" id="csrfTokenInput" />
        <button id="submitBtn" type="submit" class="w-full bg-blue-600 text-white py-3 px-4 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition duration-200">Login</button> <!-- py-2 to py-3 -->
      </form>
      
      <!-- reCAPTCHA notice -->
      <div class="recaptcha-info mt-4">
        This site is protected by reCAPTCHA and the Google 
        <a href="https://policies.google.com/privacy" target="_blank">Privacy Policy</a> and 
        <a href="https://policies.google.com/terms" target="_blank">Terms of Service</a> apply.
      </div>

      <!-- MFA Form (hidden by default) -->
      <div id="mfaForm" class="hidden">
        <h3 id="mfaFormTitle" class="text-xl font-semibold mb-4 text-center">Enter MFA Code</h3> <!-- text-lg to text-xl -->
        <form id="mfaVerifyForm" method="POST" action="/login/mfa" autocomplete="off">
          <div id="mfaCodeEntry" class="mb-4">
            <label for="mfaCodeInput" class="block mb-1 font-semibold text-gray-700">MFA Code</label>
            <input id="mfaCodeInput" name="mfa_code" type="text" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-center text-lg tracking-widest" maxlength="6" placeholder="000000" required />
            <p class="text-sm text-gray-600 mt-1">Enter the 6-digit code from your authenticator app.</p>
          </div>
          <div id="mfaRecoveryCodeEntry" class="mb-4 hidden">
            <label for="mfaRecoveryCodeInput" class="block mb-1 font-semibold text-gray-700">Recovery Code</label>
            <input id="mfaRecoveryCodeInput" name="mfa_recovery_code" type="text" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-center text-lg" placeholder="e.g. ABCDE12345" />
            <p class="text-sm text-gray-600 mt-1">Enter one of your recovery codes.</p>
          </div>
          <div class="text-center mb-4">
            <a href="#" id="toggleMfaInputLink" class="text-sm text-blue-600 hover:text-blue-800 underline">Use a recovery code</a>
          </div>
          <input type="hidden" name="csrf_token" id="mfaCsrfTokenInput" />
          <button type="submit" class="w-full bg-green-600 text-white py-3 px-4 rounded-md hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-green-500 focus:ring-offset-2 transition duration-200">Verify</button> <!-- py-2 to py-3 -->
          <button type="button" id="backToLoginBtn" class="w-full mt-3 bg-gray-600 text-white py-3 px-4 rounded-md hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-offset-2 transition duration-200">Back to Login</button> <!-- py-2 to py-3, Added mt-3 -->
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

<script src="/static/js/login_page.js" defer></script>
</body>
</html>
