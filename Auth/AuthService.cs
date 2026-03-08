// SafeVault/Auth/AuthService.cs
// Handles password hashing (BCrypt) and JWT token generation/validation.

using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using BCrypt.Net;

namespace SafeVault.Auth
{
    public class AuthService
    {
        // Store this in environment variables / secrets manager — never hardcode in production
        private const string JwtSecret = "SafeVault-Super-Secret-Key-2024!";
        private const int    TokenExpiryMinutes = 60;

        // ---------------------------------------------------------------
        // PASSWORD HASHING (BCrypt with work factor 12)
        // ---------------------------------------------------------------

        /// <summary>
        /// Hashes a plaintext password. Store the returned hash in the database.
        /// BCrypt automatically generates and embeds a random salt.
        /// </summary>
        public string HashPassword(string plainTextPassword)
        {
            if (string.IsNullOrWhiteSpace(plainTextPassword))
                throw new ArgumentException("Password cannot be empty.");

            return BCrypt.Net.BCrypt.HashPassword(plainTextPassword, workFactor: 12);
        }

        /// <summary>
        /// Verifies a plaintext password against a stored BCrypt hash.
        /// Returns true only when the password matches.
        /// </summary>
        public bool VerifyPassword(string plainTextPassword, string storedHash)
        {
            if (string.IsNullOrWhiteSpace(plainTextPassword) ||
                string.IsNullOrWhiteSpace(storedHash))
                return false;

            return BCrypt.Net.BCrypt.Verify(plainTextPassword, storedHash);
        }

        // ---------------------------------------------------------------
        // JWT TOKEN GENERATION & VALIDATION
        // ---------------------------------------------------------------

        /// <summary>
        /// Issues a signed JWT containing the user's ID and role.
        /// Token expires after TokenExpiryMinutes.
        /// </summary>
        public string GenerateJwtToken(int userId, string username, string role)
        {
            var key         = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JwtSecret));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()),
                new Claim(JwtRegisteredClaimNames.UniqueName, username),
                new Claim(ClaimTypes.Role, role),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(
                issuer:   "SafeVault",
                audience: "SafeVault",
                claims:   claims,
                expires:  DateTime.UtcNow.AddMinutes(TokenExpiryMinutes),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        /// <summary>
        /// Validates a JWT and returns the ClaimsPrincipal if valid, null if not.
        /// </summary>
        public ClaimsPrincipal ValidateJwtToken(string token)
        {
            try
            {
                var key     = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JwtSecret));
                var handler = new JwtSecurityTokenHandler();

                var principal = handler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuer           = true,
                    ValidIssuer              = "SafeVault",
                    ValidateAudience         = true,
                    ValidAudience            = "SafeVault",
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey         = key,
                    ValidateLifetime         = true,
                    ClockSkew                = TimeSpan.Zero   // No grace period
                }, out _);

                return principal;
            }
            catch
            {
                return null; // Invalid or expired token
            }
        }
    }
}
