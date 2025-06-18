<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Register - My Lapis App</title>
  <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
  <script src="https://www.google.com/recaptcha/api.js?render=<%= recaptcha_site_key %>"></script>
</head>
<body class="bg-gray-50 font-sans leading-normal tracking-normal"> <!-- bg-gray-100 to bg-gray-50 -->
  <div class="container mx-auto p-4">
    <div class="max-w-md mx-auto mt-16 bg-white p-10 rounded shadow"> <!-- mt-10 to mt-16, p-8 to p-10 -->
  <h2 class="text-3xl font-bold mb-6 text-center">Register</h2> <!-- text-2xl to text-3xl -->
  
  <form id="registerForm" method="POST" action="/register" autocomplete="off">
    <div class="mb-6"> <!-- mb-4 to mb-6 -->
      <label class="block mb-1 font-semibold text-gray-700">Username</label>
      <input name="username" type="text" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent" required pattern="[A-Za-z0-9_]{3,20}" />
      <p class="text-sm text-gray-600 mt-1">3-20 characters, letters, numbers, and underscores only</p>
    </div>
    <div class="mb-6"> <!-- mb-4 to mb-6 -->
      <label class="block mb-1 font-semibold text-gray-700">Email</label>
      <input name="email" type="email" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent" required />
    </div>
    <div class="mb-6"> <!-- mb-4 to mb-6 -->
      <label class="block mb-1 font-semibold text-gray-700">Password</label>
      <input id="password" name="password" type="password" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent" required minlength="10" />
      <div class="h-2 bg-gray-200 rounded mt-2">
        <div id="pwStrengthBar" class="h-2 rounded bg-red-400 w-0 transition-all"></div>
      </div>
      <ul class="text-sm mt-2" id="pwReqs"> <!-- text-xs to text-sm -->
        <li id="reqLen" class="text-gray-500">• At least 10 characters</li>
        <li id="reqUpper" class="text-gray-500">• At least one uppercase letter</li>
        <li id="reqNum" class="text-gray-500">• At least one number</li>
        <li id="reqSym" class="text-gray-500">• At least one special character</li>
      </ul>
    </div>
    <div class="mb-6"> <!-- mb-4 to mb-6 -->
      <label class="block mb-1 font-semibold text-gray-700">Confirm Password</label>
      <input id="confirmPassword" name="confirm_password" type="password" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent" required />
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
    <input type="text" name="website" class="hidden" autocomplete="off" tabindex="-1" /> <!-- Honeypot -->
    <input type="hidden" name="csrf_token" id="csrfTokenInput" />
    <button id="submitBtn" type="submit" class="w-full bg-green-600 text-white py-3 px-4 rounded-md hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-green-500 focus:ring-offset-2 transition duration-200" disabled>Register</button> <!-- py-2 to py-3 -->
  </form>

  <!-- Navigation Links -->
  <div class="mt-6 text-center">
    <p class="text-gray-600">Already have an account? 
      <a href="/login" class="text-blue-600 hover:text-blue-800 underline font-semibold">Sign in here</a>
    </p>
  </div>
</div>

<script src="/static/password_strength.js"></script>
<script src="/static/js/register_page.js" defer></script>
  </div>
</body>
</html>
