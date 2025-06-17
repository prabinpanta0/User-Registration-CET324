<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MFA Setup - My Lapis App</title>
  <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head>
<body class="bg-gray-50 font-sans leading-normal tracking-normal"> <!-- Changed bg-gray-100 to bg-gray-50 -->
  <div class="container mx-auto p-4">
    <div class="max-w-md mx-auto mt-16 bg-white p-10 rounded shadow"> <!-- mt-10 to mt-16, p-8 to p-10 -->
  <h2 class="text-3xl font-bold mb-6 text-center">Set Up Multi-Factor Authentication</h2> <!-- text-2xl to text-3xl -->
  <p class="text-gray-700 mb-8 text-center">To complete your registration and secure your account, please set up two-factor authentication.</p> <!-- text-gray-600 to text-gray-700, mb-6 to mb-8 -->
  <div id="mfaSetup">
    <div class="mb-8"> <!-- mb-4 to mb-8 -->
      <label class="block mb-1 font-semibold text-gray-700">Scan QR Code with Authenticator App</label>
      <div id="qrContainer" class="flex justify-center bg-white p-6 border border-gray-400 rounded-md"></div> <!-- p-4 to p-6, border-gray-300 to border-gray-400 -->
      <p class="text-sm text-gray-600 mt-2">Use apps like Google Authenticator, Authy, or Microsoft Authenticator</p>
    </div>
    <div class="mb-8"> <!-- mb-4 to mb-8 -->
      <label class="block mb-1 mt-6 font-semibold text-gray-700">Or enter this secret manually:</label> <!-- Added mt-6 -->
      <input id="mfaSecret" type="text" class="w-full px-3 py-2 border border-gray-300 rounded-md bg-gray-50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-lg" readonly /> <!-- Added text-lg -->
    </div>
    <form id="verifyMfaForm" method="POST" action="/mfa/verify" autocomplete="off">
      <div class="mb-6"> <!-- mb-4 to mb-6 -->
        <label class="block mb-1 font-semibold text-gray-700">Enter code from your app</label>
        <input name="code" type="text" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-center text-lg tracking-widest" maxlength="6" placeholder="000000" required />
        <p class="text-sm text-gray-600 mt-2">Enter the 6-digit code from your authenticator app</p> <!-- mt-1 to mt-2 -->
      </div>
      <input type="hidden" name="csrf_token" id="csrfTokenInput" />
      <button type="submit" class="w-full bg-blue-600 text-white py-3 px-4 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition duration-200">Verify & Enable MFA</button> <!-- py-2 to py-3 -->
    </form>
  </div>

  <!-- Recovery Codes Section (Initially Hidden) -->
  <div id="recoveryCodesSection" class="hidden mt-8">
    <h3 class="text-2xl font-bold mb-4 text-center text-green-600">MFA Enabled Successfully!</h3>
    <p class="text-gray-700 mb-4 text-center">Below are your recovery codes. Each code can be used once if you lose access to your authenticator app. <strong class="font-semibold">Save these codes in a very safe place. You will not be shown them again.</strong></p>

    <div class="mb-4 p-4 border border-gray-300 rounded bg-gray-50 max-h-48 overflow-y-auto">
        <ul id="recoveryCodeList" class="space-y-2">
            <!-- Codes will be populated here by JavaScript -->
        </ul>
    </div>

    <div class="flex flex-col sm:flex-row gap-3 mb-6">
        <button id="copyRecoveryCodesBtn" class="w-full sm:w-auto flex-1 bg-indigo-600 text-white py-2 px-4 rounded-md hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 transition duration-200">Copy Codes</button>
        <button id="downloadRecoveryCodesBtn" class="w-full sm:w-auto flex-1 bg-gray-600 text-white py-2 px-4 rounded-md hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-offset-2 transition duration-200">Download Codes</button>
    </div>
    
    <button id="proceedToDashboardBtn" class="w-full bg-green-600 text-white py-3 px-4 rounded-md hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-green-500 focus:ring-offset-2 transition duration-200">Done, Proceed to Dashboard</button>
  </div>
</div>
<script src="/static/qrcode.min.js"></script>
<script src="/static/js/mfa_setup_page.js" defer></script>
  </div>
</body>
</html>
