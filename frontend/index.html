<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <title>User Registration</title>
    <link rel="stylesheet" href="styles.css" />
</head>
<body>
    <div class="container">
        <h2>Register</h2>
        <form id="registrationForm">
            <div class="input-group">
                <label for="username">Username</label>
                <input type="text" name="username" id="username" placeholder="Enter your username" required />
            </div>
            <div class="input-group">
                <label for="email">Email</label>
                <input type="email" name="email" id="email" placeholder="Enter your email" required />
            </div>
            <div class="input-group">
                <label for="password">Password</label>
                <input type="password" name="password" id="password" placeholder="Enter your password" required />
            </div>
            <button type="submit">Register</button>
        </form>
        <div id="message"></div>
    </div>

    <script>
        document.getElementById('registrationForm').addEventListener('submit', async function(event) {
            event.preventDefault();
            const form = event.target;
            const formData = new FormData(form);
            const data = Object.fromEntries(formData.entries());

            const messageDiv = document.getElementById('message');
            messageDiv.textContent = '';
            messageDiv.style.color = '';

            try {
                const response = await fetch('https://registratin-backend.onrender.com/api/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });

                const result = await response.json();

                if(response.ok){
                    messageDiv.style.color = 'green';
                    messageDiv.textContent = '✅ Registration successful!';
                    form.reset();
                } else {
                    messageDiv.style.color = 'red';
                    messageDiv.textContent = '❌ ' + result.message;
                }
            } catch (error) {
                messageDiv.style.color = 'red';
                messageDiv.textContent = '❌ Network error. Please try again later.';
            }
        });
    </script>
</body>
</html>
