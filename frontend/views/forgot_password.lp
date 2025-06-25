<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Forgot Password - My Lapis App</title>
  <link rel="icon" type="image/x-icon" href="/favicon.ico">
  <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
  <link rel="stylesheet" href="/static/tailwind.css">
</head>
<body class="bg-gray-50 font-sans leading-normal tracking-normal">
  <div class="container mx-auto p-4">
    <div class="max-w-md mx-auto mt-16 bg-white p-10 rounded shadow">
      <h2 class="text-3xl font-bold mb-6 text-center">Reset Your Password</h2>
      <p class="text-gray-700 mb-4">Enter your email address below and we'll send you instructions to reset your password.</p>
      <form id="forgotPasswordForm" method="POST" action="/forgot-password" class="space-y-4">
        <div>
          <label class="block mb-1 font-semibold text-gray-700">Email Address</label>
          <input name="email" type="email" required class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent" placeholder="you@example.com" />
        </div>
        <button type="submit" class="w-full bg-blue-600 text-white py-3 px-4 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition duration-200">Send Reset Link</button>
      </form>
      <div id="forgotMessage" class="hidden mt-4 p-4 bg-green-100 border border-green-400 text-green-700 rounded">
        Email sent, check your mail to change your password.
      </div>
      <div class="mt-6 text-center">
        <a href="/login" class="text-sm text-blue-600 hover:text-blue-800 underline">Back to Login</a>
      </div>
    </div>
  </div>
  <script>
    document.addEventListener('DOMContentLoaded', function() {
      const form = document.getElementById('forgotPasswordForm');
      const msgDiv = document.getElementById('forgotMessage');
      form.addEventListener('submit', function(e) {
        e.preventDefault();
        form.classList.add('hidden');
        msgDiv.classList.remove('hidden');
      });
    });
  </script>
</body>
</html>
