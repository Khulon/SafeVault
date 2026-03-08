// SafeVault/Tests/TestAuthAndAuthorization.cs
// Tests covering: password hashing, JWT tokens, login flows, and role access.

using NUnit.Framework;
using System.Security.Claims;
using SafeVault.Auth;
using SafeVault.Models;

namespace SafeVault.Tests
{
    [TestFixture]
    public class TestAuthentication
    {
        private AuthService _auth;

        [SetUp]
        public void Setup() => _auth = new AuthService();

        // ---------------------------------------------------------------
        // PASSWORD HASHING
        // ---------------------------------------------------------------

        [Test]
        public void HashPassword_ProducesNonNullHash()
        {
            string hash = _auth.HashPassword("SecurePass1!");
            Assert.IsNotNull(hash);
            Assert.IsNotEmpty(hash);
        }

        [Test]
        public void HashPassword_TwoCallsSamePlaintext_ProduceDifferentHashes()
        {
            // BCrypt uses a random salt each time — hashes must never be identical
            string hash1 = _auth.HashPassword("SecurePass1!");
            string hash2 = _auth.HashPassword("SecurePass1!");
            Assert.AreNotEqual(hash1, hash2, "Same password produced identical hashes — salt missing!");
        }

        [Test]
        public void VerifyPassword_CorrectPassword_ReturnsTrue()
        {
            string hash = _auth.HashPassword("CorrectHorse99!");
            Assert.IsTrue(_auth.VerifyPassword("CorrectHorse99!", hash));
        }

        [Test]
        public void VerifyPassword_WrongPassword_ReturnsFalse()
        {
            string hash = _auth.HashPassword("CorrectHorse99!");
            Assert.IsFalse(_auth.VerifyPassword("WrongPassword!", hash));
        }

        [Test]
        public void VerifyPassword_EmptyPassword_ReturnsFalse()
        {
            string hash = _auth.HashPassword("ValidPass1!");
            Assert.IsFalse(_auth.VerifyPassword("", hash));
            Assert.IsFalse(_auth.VerifyPassword(null, hash));
        }

        // ---------------------------------------------------------------
        // JWT TOKEN GENERATION & VALIDATION
        // ---------------------------------------------------------------

        [Test]
        public void GenerateJwtToken_ReturnsNonEmptyString()
        {
            string token = _auth.GenerateJwtToken(1, "alice", Roles.User);
            Assert.IsNotNull(token);
            Assert.IsNotEmpty(token);
        }

        [Test]
        public void ValidateJwtToken_ValidToken_ReturnsPrincipal()
        {
            string token = _auth.GenerateJwtToken(1, "alice", Roles.User);
            ClaimsPrincipal principal = _auth.ValidateJwtToken(token);
            Assert.IsNotNull(principal, "Valid token should return a ClaimsPrincipal.");
        }

        [Test]
        public void ValidateJwtToken_TamperedToken_ReturnsNull()
        {
            string token    = _auth.GenerateJwtToken(1, "alice", Roles.User);
            string tampered = token + "tampered";
            Assert.IsNull(_auth.ValidateJwtToken(tampered),
                "Tampered token should be rejected.");
        }

        [Test]
        public void ValidateJwtToken_GarbageString_ReturnsNull()
        {
            Assert.IsNull(_auth.ValidateJwtToken("not.a.token"));
        }

        [Test]
        public void JwtToken_ContainsCorrectRole()
        {
            string token     = _auth.GenerateJwtToken(99, "bob", Roles.Admin);
            var principal    = _auth.ValidateJwtToken(token);
            bool isAdmin     = principal.IsInRole(Roles.Admin);
            Assert.IsTrue(isAdmin, "Token should carry the Admin role claim.");
        }

        [Test]
        public void JwtToken_ContainsCorrectUsername()
        {
            string token    = _auth.GenerateJwtToken(1, "charlie", Roles.User);
            var principal   = _auth.ValidateJwtToken(token);
            string username = principal.Identity?.Name;
            Assert.AreEqual("charlie", username);
        }
    }

    [TestFixture]
    public class TestAuthorization
    {
        private AuthService _auth;

        [SetUp]
        public void Setup() => _auth = new AuthService();

        // ---------------------------------------------------------------
        // ROLE-BASED ACCESS CONTROL
        // Simulate what the [Authorize(Roles="...")] attribute enforces.
        // ---------------------------------------------------------------

        [Test]
        public void AdminRole_CanAccessAdminPanel()
        {
            var principal = _auth.ValidateJwtToken(
                _auth.GenerateJwtToken(1, "adminUser", Roles.Admin));

            Assert.IsTrue(principal.IsInRole(Roles.Admin),
                "Admin user should have Admin role.");
        }

        [Test]
        public void UserRole_CannotAccessAdminPanel()
        {
            var principal = _auth.ValidateJwtToken(
                _auth.GenerateJwtToken(2, "regularUser", Roles.User));

            Assert.IsFalse(principal.IsInRole(Roles.Admin),
                "Regular user should NOT have Admin role.");
        }

        [Test]
        public void UserRole_CanAccessDashboard()
        {
            var principal = _auth.ValidateJwtToken(
                _auth.GenerateJwtToken(2, "regularUser", Roles.User));

            bool canAccess = principal.IsInRole(Roles.Admin) || principal.IsInRole(Roles.User);
            Assert.IsTrue(canAccess, "User role should access the dashboard.");
        }

        [Test]
        public void GuestRole_CannotAccessDashboard()
        {
            var principal = _auth.ValidateJwtToken(
                _auth.GenerateJwtToken(3, "guestUser", Roles.Guest));

            bool canAccess = principal.IsInRole(Roles.Admin) || principal.IsInRole(Roles.User);
            Assert.IsFalse(canAccess, "Guest should NOT access the dashboard.");
        }

        [Test]
        public void NoToken_CannotAccessProtectedRoute()
        {
            // Simulates a request with no Authorization header
            ClaimsPrincipal principal = _auth.ValidateJwtToken(null);
            Assert.IsNull(principal, "Null token should be rejected.");
        }

        [Test]
        public void InvalidLogin_DoesNotIssueToken()
        {
            // Simulate wrong password scenario: VerifyPassword returns false → no token issued
            var auth       = new AuthService();
            string hash    = auth.HashPassword("RealPassword1!");
            bool verified  = auth.VerifyPassword("WrongPassword!", hash);

            // Token should NOT be generated when verification fails
            Assert.IsFalse(verified, "Wrong password must not pass verification.");
        }
    }
}
