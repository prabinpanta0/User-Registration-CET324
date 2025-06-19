<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Email Verification - My Lapis App</title>
  <link rel="icon" type="image/x-icon" href="/favicon.ico">
  <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
  <link rel="stylesheet" type="text/css" href="https://cdn.jsdelivr.net/npm/toastify-js/src/toastify.min.css">
  <link rel="stylesheet" href="/static/tailwind.css">
</head>
<body class="bg-gray-50 font-sans leading-normal tracking-normal">
  <div class="container mx-auto p-4">
    <div class="max-w-md mx-auto mt-16 bg-white p-10 rounded shadow">
      <div class="text-center">
        <!-- Verification via URL token (automatic) OR code input -->
        <div id="verification-status">
          <div class="text-center">
            <svg class="mx-auto h-16 w-16 mb-4 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 4.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2 2v10a2 2 0 002 2z"></path>
            </svg>
            <h2 class="text-2xl font-bold mb-2">Verifying Email...</h2>
            <p class="text-gray-600 mb-4">Please wait while we verify your email address.</p>
            <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto"></div>
          </div>
        </div>
        
        <!-- Verification code form (hidden by default, shown if no token) -->
        <div id="verification-form" class="mt-6 hidden">
          <form id="verifyEmailForm" class="space-y-4">
            <div>
              <svg class="mx-auto h-16 w-16 mb-4 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 4.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path>
              </svg>
              <h2 class="text-2xl font-bold mb-2">Enter Verification Code</h2>
              <p class="text-gray-600 mb-4">Please enter the 6-digit code sent to your email address.</p>
            </div>
            
            <div>
              <label class="block mb-1 font-semibold text-gray-700">Verification Code</label>
              <input id="codeInput" name="code" type="text" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-center text-lg tracking-widest" required maxlength="6" pattern="[0-9]{6}" placeholder="000000" />
            </div>
            
            <input type="hidden" name="csrf_token" id="csrfTokenInput" />
            
            <button id="verifyBtn" type="submit" class="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition duration-200">
              Verify Email
            </button>
          </form>
          
          <div class="mt-4 text-center">
            <a href="/login" class="text-sm text-blue-600 hover:text-blue-800 underline">Back to Login</a>
          </div>
        </div>
        
        <!-- Default navigation - will be replaced by JavaScript if needed -->
        <div id="default-nav" class="mt-6 hidden">
          <a href="/login" class="inline-block bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition duration-200">
            Go to Login
          </a>
        </div>
      </div>
    </div>
  </div>

  <script type="text/javascript" src="https://cdn.jsdelivr.net/npm/toastify-js"></script>
  <script src="/static/js/email_verification_page.js?v=2"></script>
</body>
</html>
