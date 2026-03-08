// SafeVault/Models/User.cs
// User model with role assignment.

namespace SafeVault.Models
{
    public class User
    {
        public int    UserID       { get; set; }
        public string Username     { get; set; }
        public string Email        { get; set; }
        public string PasswordHash { get; set; }
        public string Role         { get; set; }  // "Admin", "User", "Guest"
        public bool   IsActive     { get; set; } = true;
    }

    // Centralised role constants — avoids magic strings throughout the codebase
    public static class Roles
    {
        public const string Admin = "Admin";
        public const string User  = "User";
        public const string Guest = "Guest";
    }
}
