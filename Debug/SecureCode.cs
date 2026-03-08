// SafeVault/Debug/SecureCode.cs
// ✅ FIXED versions of every vulnerability in VulnerableCode.cs
// Each fix is annotated with the vulnerability it addresses.

using System;
using System.Data;
using System.Data.SqlClient;
using System.Web;
using SafeVault.Helpers;

namespace SafeVault.Debug
{
    public class SecureCode
    {
        private readonly string _connectionString;
        public SecureCode(string connectionString) => _connectionString = connectionString;

        // ---------------------------------------------------------------
        // FIX 1: Parameterized query — eliminates SQL injection
        // User input is passed as a typed parameter, never into the SQL string.
        // ---------------------------------------------------------------
        public object GetUserSecure(string username)
        {
            // ✅ Validate format first (reuse Activity 1 helper)
            if (!ValidationHelpers.IsValidUsername(username))
                throw new ArgumentException("Invalid username.");

            // ✅ Parameter placeholder — SQL engine treats value as data, not code
            const string query = "SELECT UserID, Username, Email FROM Users WHERE Username = @Username";

            using (var conn = new SqlConnection(_connectionString))
            using (var cmd  = new SqlCommand(query, conn))
            {
                cmd.Parameters.Add("@Username", SqlDbType.NVarChar, 100).Value = username;
                conn.Open();
                return cmd.ExecuteScalar();
            }
        }

        // ---------------------------------------------------------------
        // FIX 2: HTML encoding — eliminates XSS
        // HttpUtility.HtmlEncode converts < > " ' & into safe HTML entities.
        // ---------------------------------------------------------------
        public string RenderGreetingSecure(string username)
        {
            // ✅ Encode before embedding in HTML
            string safeUsername = HttpUtility.HtmlEncode(username);
            return "<h1>Welcome, " + safeUsername + "!</h1>";
        }

        // ---------------------------------------------------------------
        // FIX 3: Validation + parameterized login — eliminates both issues
        // ---------------------------------------------------------------
        public bool LoginSecure(string username, string passwordHash)
        {
            // ✅ Reject invalid format before touching the database
            if (!ValidationHelpers.IsValidUsername(username))
                return false;

            if (string.IsNullOrWhiteSpace(passwordHash) || passwordHash.Length > 256)
                return false;

            // ✅ Parameterized query — no concatenation
            const string query = @"
                SELECT COUNT(1) FROM Users
                WHERE  Username     = @Username
                AND    PasswordHash = @PasswordHash
                AND    IsActive     = 1";

            using (var conn = new SqlConnection(_connectionString))
            using (var cmd  = new SqlCommand(query, conn))
            {
                cmd.Parameters.Add("@Username",     SqlDbType.NVarChar, 100).Value = username;
                cmd.Parameters.Add("@PasswordHash", SqlDbType.NVarChar, 256).Value = passwordHash;
                conn.Open();
                return (int)cmd.ExecuteScalar() > 0;
            }
        }
    }
}
