// SafeVault/Controllers/AuthController.cs
// Handles login, token issuance, and role-based route protection.

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Auth;
using SafeVault.Data;
using SafeVault.Helpers;
using SafeVault.Models;

namespace SafeVault.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly AuthService     _authService;
        private readonly UserRepository  _userRepo;

        public AuthController(AuthService authService, UserRepository userRepo)
        {
            _authService = authService;
            _userRepo    = userRepo;
        }

        // ---------------------------------------------------------------
        // POST /api/auth/register
        // ---------------------------------------------------------------
        [HttpPost("register")]
        [AllowAnonymous]
        public IActionResult Register([FromBody] RegisterRequest req)
        {
            // Validate inputs (reuses Activity 1 helpers)
            if (!ValidationHelpers.IsValidUsername(req.Username))
                return BadRequest("Invalid username.");

            if (!ValidationHelpers.IsValidEmail(req.Email))
                return BadRequest("Invalid email address.");

            if (string.IsNullOrWhiteSpace(req.Password) || req.Password.Length < 8)
                return BadRequest("Password must be at least 8 characters.");

            string hash = _authService.HashPassword(req.Password);

            bool created = _userRepo.CreateUser(req.Username, req.Email, hash, Roles.User);
            if (!created)
                return Conflict("Username or email already exists.");

            return Ok("Registration successful.");
        }

        // ---------------------------------------------------------------
        // POST /api/auth/login
        // Returns a JWT on success.
        // ---------------------------------------------------------------
        [HttpPost("login")]
        [AllowAnonymous]
        public IActionResult Login([FromBody] LoginRequest req)
        {
            if (!ValidationHelpers.IsValidUsername(req.Username))
                return BadRequest("Invalid username.");

            User user = _userRepo.GetUserByUsername(req.Username);

            // Check existence, active status, and password hash in one block
            // to avoid user-enumeration timing differences
            if (user == null || !user.IsActive ||
                !_authService.VerifyPassword(req.Password, user.PasswordHash))
            {
                return Unauthorized("Invalid credentials.");
            }

            string token = _authService.GenerateJwtToken(user.UserID, user.Username, user.Role);
            return Ok(new { token });
        }

        // ---------------------------------------------------------------
        // GET /api/auth/dashboard
        // Accessible by any authenticated user (Admin or User role).
        // ---------------------------------------------------------------
        [HttpGet("dashboard")]
        [Authorize(Roles = "Admin,User")]
        public IActionResult Dashboard()
        {
            var username = User.Identity?.Name ?? "unknown";
            return Ok($"Welcome to your dashboard, {username}.");
        }

        // ---------------------------------------------------------------
        // GET /api/auth/admin
        // Accessible by Admin role ONLY.
        // ---------------------------------------------------------------
        [HttpGet("admin")]
        [Authorize(Roles = "Admin")]
        public IActionResult AdminPanel()
        {
            return Ok("Admin panel: full access granted.");
        }
    }

    // ---------------------------------------------------------------
    // Request DTOs
    // ---------------------------------------------------------------
    public class LoginRequest
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public class RegisterRequest
    {
        public string Username { get; set; }
        public string Email    { get; set; }
        public string Password { get; set; }
    }
}
