// Password strength checker
document.getElementById('password')?.addEventListener('input', function() {
    const strengthIndicator = document.getElementById('password-strength');
    if (!strengthIndicator) return;

    const strength = {
        0: "Very Weak",
        1: "Weak",
        2: "Moderate",
        3: "Strong",
        4: "Very Strong"
    };
    
    let score = 0;
    const password = this.value;

    // Check password length
    if (password.length > 0) score++;
    if (password.length >= 8) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/\d/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;

    strengthIndicator.textContent = strength[Math.min(score, 4)];
    strengthIndicator.className = `text-${[
        'red-500',    // 0
        'orange-500', // 1
        'yellow-500', // 2
        'blue-500',   // 3
        'green-500'   // 4
    ][Math.min(score, 4)]}`;
});

// Confirm password match
document.getElementById('confirm-password')?.addEventListener('input', function() {
    const password = document.getElementById('password').value;
    const confirmPassword = this.value;
    const matchIndicator = document.getElementById('password-match');
    
    if (!matchIndicator) return;
    
    if (confirmPassword === '') {
        matchIndicator.textContent = '';
    } else if (password === confirmPassword) {
        matchIndicator.textContent = 'Passwords match';
        matchIndicator.className = 'text-green-500 text-sm';
    } else {
        matchIndicator.textContent = 'Passwords do not match';
        matchIndicator.className = 'text-red-500 text-sm';
    }
});