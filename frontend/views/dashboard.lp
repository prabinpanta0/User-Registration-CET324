<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Dashboard - My Lapis App</title>
  <link rel="icon" type="image/x-icon" href="/favicon.ico">
  <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
  <link rel="stylesheet" href="/static/tailwind.css">
</head>
<body class="bg-gray-100 font-sans leading-normal tracking-normal">
  <div class="container mx-auto p-4">
    <div class="max-w-xl mx-auto mt-10 bg-white p-8 rounded shadow">
  <div class="flex justify-between items-center mb-6">
    <h2 class="text-2xl font-bold">Dashboard</h2>
    <div class="flex gap-2">
      <button id="logoutBtn" class="text-sm bg-red-600 text-white px-3 py-1 rounded hover:bg-red-700">Logout</button>
    </div>
  </div>

  <div id="userInfo" class="mb-6 p-4 bg-gray-50 rounded">
    <h3 class="text-lg font-semibold mb-3">Account Information</h3>
    <div class="space-y-2">
      <p><span class="font-semibold text-gray-700">Username:</span> <span id="username" class="text-gray-900">Loading...</span></p>
      <p><span class="font-semibold text-gray-700">Email:</span> <span id="email" class="text-gray-900">Loading...</span></p>
      <p><span class="font-semibold text-gray-700">Last Login:</span> <span id="lastLogin" class="text-gray-900">Loading...</span></p>
      <p><span class="font-semibold text-gray-700">MFA Enabled:</span> <span id="mfaStatus" class="text-gray-900">Loading...</span></p>
    </div>
  </div>

  <div id="sessionManager" class="mb-6 p-4 bg-gray-50 rounded">
    <h3 class="text-lg font-semibold mb-3">Active Sessions</h3>
    <ul id="sessionList" class="text-sm space-y-1">
      <li class="text-gray-600">Loading sessions...</li>
    </ul>
  </div>

  <!-- MFA Recovery Codes Section (hidden by default, shown if MFA is enabled) -->
  <div id="mfaRecoverySection" class="hidden mt-6 p-4 bg-gray-50 rounded">
    <h3 class="text-lg font-semibold mb-3">MFA Recovery Codes</h3>
    <p id="recoveryCodesStatus" class="text-sm text-gray-700 mb-3">Loading status...</p>
    <button id="regenerateRecoveryCodesBtn" class="text-sm bg-orange-500 text-white px-4 py-2 rounded hover:bg-orange-600 focus:outline-none focus:ring-2 focus:ring-orange-400 focus:ring-offset-2">Regenerate Codes</button>
    <button id="downloadExistingRecoveryCodesBtn" class="text-sm bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:ring-offset-2 ml-2">Download Codes</button>

    <!-- Modal or area to display newly regenerated codes -->
    <div id="newRecoveryCodesDisplay" class="hidden mt-4 p-4 border border-gray-300 rounded bg-white">
      <h4 class="text-md font-semibold mb-2 text-green-600">New Recovery Codes Generated!</h4>
      <p class="text-gray-700 mb-2 text-sm"><strong class="font-semibold">Save these codes in a very safe place. You will not be shown them again.</strong> Each code can be used once.</p>
      <ul id="newRecoveryCodeList" class="space-y-1 list-disc list-inside mb-3 max-h-32 overflow-y-auto">
        <!-- New codes will be populated here -->
      </ul>
      <div class="flex flex-col sm:flex-row gap-2">
        <button id="copyNewRecoveryCodesBtn" class="w-full sm:w-auto flex-1 text-sm bg-indigo-500 text-white px-3 py-1 rounded hover:bg-indigo-600">Copy Codes</button>
        <button id="downloadNewRecoveryCodesBtn" class="w-full sm:w-auto flex-1 text-sm bg-gray-500 text-white px-3 py-1 rounded hover:bg-gray-600">Download Codes</button>
      </div>
      <button id="closeNewRecoveryCodesBtn" class="mt-3 text-sm text-blue-600 hover:text-blue-800 underline">Done</button>
    </div>
  </div>
</div>

<script src="/static/js/dashboard_page.js" defer></script>
  </div>
</body>
</html>
