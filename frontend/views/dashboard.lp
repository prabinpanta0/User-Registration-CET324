<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Dashboard - My Lapis App</title>
  <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head>
<body class="bg-gray-100 font-sans leading-normal tracking-normal">
  <div class="container mx-auto p-4">
    <div class="max-w-xl mx-auto mt-10 bg-white p-8 rounded shadow">
  <div class="flex justify-between items-center mb-6">
    <h2 class="text-2xl font-bold">Dashboard</h2>
    <div class="flex gap-2">
      <button onclick="logout()" class="text-sm bg-red-600 text-white px-3 py-1 rounded hover:bg-red-700">Logout</button>
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

</div>

<script>
function logout() {
  fetch('/logout', {
    method: 'POST',
    credentials: 'include'
  }).then(() => {
    window.location = '/login';
  });
}

// Fetch user info
fetch('/dashboard/info', {credentials: 'include'})
  .then(r => {
    if (r.ok) {
      return r.json();
    } else {
      // If not authenticated, redirect to login
      window.location = '/login';
      throw new Error('Not authenticated');
    }
  })
  .then(data => {
    document.getElementById('username').textContent = data.username || 'N/A';
    document.getElementById('email').textContent = data.email || 'N/A';
    document.getElementById('lastLogin').textContent = data.last_login || 'N/A';
    document.getElementById('mfaStatus').textContent = data.mfa_enabled ? 'Yes' : 'No';
  })
  .catch(err => {
    console.error('Failed to load user info:', err);
    document.getElementById('username').textContent = 'Error loading';
    document.getElementById('email').textContent = 'Error loading';
    document.getElementById('lastLogin').textContent = 'Error loading';
    document.getElementById('mfaStatus').textContent = 'Error loading';
  });

// Load active sessions
function loadSessions() {
  fetch('/dashboard/sessions', {credentials: 'include'})
    .then(r => {
      if (!r.ok) {
        throw new Error('Failed to load sessions: ' + r.status);
      }
      return r.json();
    })
    .then(sessions => {
      const sessionList = document.getElementById('sessionList');
      if (sessions.length === 0) {
        sessionList.innerHTML = '<li class="text-gray-600">No active sessions</li>';
        return;
      }
      
      sessionList.innerHTML = sessions.map(session => {
        const currentTag = session.current ? ' <span class="text-green-600 text-xs">(Current)</span>' : '';
        const revokeButton = session.current ? 
          '<span class="text-gray-400 text-xs">Use Logout</span>' :
          `<button onclick="revokeSession('${session.id}')" class="text-red-600 hover:text-red-800 text-xs">Revoke</button>`;
        
        return `<li class="flex justify-between items-center py-1">
          <span class="text-gray-800">${session.ip} - ${session.created}${currentTag}</span>
          ${revokeButton}
        </li>`;
      }).join('');
    })
    .catch(err => {
      console.error('Failed to load sessions:', err);
      document.getElementById('sessionList').innerHTML = '<li class="text-red-600">Failed to load sessions</li>';
    });
}

function revokeSession(sessionId) {
  fetch(`/dashboard/sessions/${sessionId}/revoke`, {
    method: 'POST',
    credentials: 'include'
  })
  .then(r => {
    if (!r.ok) {
      throw new Error('Failed to revoke session: ' + r.status);
    }
    return r.text();
  })
  .then(() => {
    loadSessions(); // Reload the list
  })
  .catch(err => {
    console.error('Failed to revoke session:', err);
    alert('Failed to revoke session');
  });
}

// Load sessions on page load
loadSessions();

</script>
  </div>
</body>
</html>
