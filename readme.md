# Actix Web API with Rustls (OpenSSL available/Without SSL/TLS too)

This API uses Actix Web to serve secure HTTP endpoints, utilizing Rustls for TLS encryption. The API interfaces with a MySQL database for various functionalities.

## Features:

### TLS Configuration
The API uses Rustls for TLS encryption, leveraging the `cert.pem` certificate file and the `key.pem` private key file.

### Database Connection
The API connects to a MySQL database using `mysql_async`. The database URL is obtained from the `DATABASE_URL` environment variable. It ensures the existence of the required database and table during startup.

### CORS
Configured to accept CORS requests from `http://localhost:8084`, the API allows `GET` and `POST` methods and accepts specific headers.

### Endpoints:

1. **Forgot Password** (`/forgot_password`)
    - Generates a reset password link and sends it via email.
    - The reset link token expires in one day.
    - Uses SMTP details from environment variables.

```bash
curl -X POST "http://localhost:8084/forgot_password"      -H "Content-Type: application/json"      -d '{"email": "your_email@example.com"}'
```

2. **Login** (`/login`)
    - Validates the user's credentials and returns a JWT token upon success.
    - The JWT token expires in one day.
    - If the user hasn't verified their email, an error message is sent.

```bash
curl -X POST "http://localhost:8084/login"      -H "Content-Type: application/json"      -d '{"username": "your_username", "password": "your_password"}'
```

3. **Create Account** (`/create_account`)
    - Registers a new user, sending a verification email.
    - The verification token expires in one day.
    - SMTP details from environment variables are used for email sending.
    - Returns a JWT token upon successful registration.

```bash
curl -X POST "http://localhost:8084/create_account"      -H "Content-Type: application/json"      -d '{"username": "desired_username", "email": "your_email@example.com", "password": "desired_password"}'
```

4. **Reset Password** (`/reset_password`)
    - Users can reset their password using the token from the email.
    - Validates the token and its expiration.
    - If valid, the password is reset.

```bash
curl -X POST "http://localhost:8084/reset_password"      -H "Content-Type: application/json"      -d '{"email": "your_email@example.com", "token": "your_token", "new_password": "new_password"}'
```

5. **Resend Verification** (`/resend_verification`)
    - Resends the email verification link for users who haven't verified their account.
    - Uses SMTP details from environment variables.

```bash
curl -X POST "http://localhost:8084/resend_verification"      -H "Content-Type: application/json"      -d '{"email": "your_email@example.com"}'
```

6. **Handle Verification Link** (`/verify`)
    - Validates the verification token from the link.
    - If the token is valid and not expired, it verifies the user's email.
    - A user can only attempt verification five times.

(Note: This is a `GET` request, so you might typically just click the link in a browser. But here's how you'd do it with `curl`):

```bash
curl -X GET "http://localhost:8084/verify?token=your_verification_token"
```

Replace placeholders like `your_email@example.com`, `your_username`, `your_password`, `desired_username`, `desired_password`, `your_token`, and `your_verification_token` with the appropriate values for your tests.

### Common Utilities (`common.rs`):

This module contains common imports, error handling, and data structures such as:

- ResponseError implementation for ServiceError.
- Login, registration, forgot password, and reset password request structures.
- JWT claims data structure.
- Service errors (InternalServerError and BadRequest).

## Running the API

The API is configured to listen on `0.0.0.0:8084`.

Feel free to leave a star if you use the code <3 

## Roadmap

Our aim is to develop the most user-friendly and widely adopted login/registration API. The roadmap below outlines the features and improvements we plan to implement:

1. **Docker Integration (Completed)**: 
   - Ensure that the API is easily deployable using Docker for a consistent and isolated environment. 
   
2. **Configurable Email Verification**:
   - Allow the option to skip email verification for token confirmation during registration.
   - Give the choice between sending a verification link or a verification code in the email.

3. **Session Management for Login**:
   - Implement a robust session management system to maintain user sessions securely after login.
   
4. **Third-party Integrations for Login/Register**:
   - Integrate options for users to register/login using third-party services like Google, Facebook, etc.

5. **Modularity**: 
   - Make the API highly modular, allowing developers to easily toggle features on or off based on their requirements.

6. **Enhanced Security**:
   - Explore multi-factor authentication options.

7. **Documentation and Usage Guides**:
   - Provide comprehensive documentation and step-by-step guides to help developers integrate and deploy the API effortlessly. (There will be a public guide, but for those who want to go further and help me, a Udemy training course will probably be available in the future with examples of NextJs code with the api / Creation of an SMTP server / Creation of a deployable database also with Docker)

8. **Continuous Integration and Testing**:
   - Ensure the reliability of the API through continuous integration and rigorous testing procedures.

9. **Community Engagement**:
   - Foster an active community around the project, encouraging contributions, feedback, and feature requests.

Remember, our primary goal is ease of use while maintaining high security and flexibility. Your feedback and contributions will be invaluable in shaping the future of this project.

## License

This project is licensed under the MIT License. This means you can freely use, modify, and distribute the code, but you cannot hold the authors liable for any issues or faults. Always refer to the license document for full details.
