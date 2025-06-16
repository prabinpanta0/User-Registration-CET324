function checkPasswordStrength(pw) {
  let score = 0;
  if (pw.length >= 10) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  return score;
}

function updateStrength() {
  const pw = document.getElementById('password').value;
  const confirm = document.getElementById('confirmPassword').value;
  const bar = document.getElementById('pwStrengthBar');
  const reqLen = document.getElementById('reqLen');
  const reqUpper = document.getElementById('reqUpper');
  const reqNum = document.getElementById('reqNum');
  const reqSym = document.getElementById('reqSym');
  const submit = document.getElementById('submitBtn');

  let score = checkPasswordStrength(pw);
  bar.style.width = (score * 25) + '%';
  bar.className = 'h-2 rounded transition-all ' +
    (score === 4 ? 'bg-green-500' : score === 3 ? 'bg-yellow-400' : 'bg-red-400');

  reqLen.className = pw.length >= 10 ? 'text-green-600' : 'text-gray-500';
  reqUpper.className = /[A-Z]/.test(pw) ? 'text-green-600' : 'text-gray-500';
  reqNum.className = /[0-9]/.test(pw) ? 'text-green-600' : 'text-gray-500';
  reqSym.className = /[^A-Za-z0-9]/.test(pw) ? 'text-green-600' : 'text-gray-500';

  const allReqs = score === 4;
  const pwMatch = pw && pw === confirm;
  submit.disabled = !(allReqs && pwMatch);
}

document.getElementById('password').addEventListener('input', updateStrength);
document.getElementById('confirmPassword').addEventListener('input', updateStrength);
