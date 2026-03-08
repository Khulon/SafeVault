// SafeVault/Debug/VulnerableCode.cs
// ⚠️  INTENTIONALLY INSECURE — for educational comparison only.
// These patterns show what NOT to do. See SecureCode.cs for the fixes.

using System.Data.SqlClient;
using System.Web;

namespace SafeVault.Debug
{
    public class VulnerableCode
    {
        private readonly string _connectionString;
        public VulnerableCode(string connectionString) => _connectionString = connectionString;

        // ---------------------------------------------------------------
        // VULNERABILITY 1: SQL Injection via string concatenation
        // Attacker input: ' OR '1'='1  → returns ALL users
        // Attacker input: '; DROP TABLE Users;-- → deletes the table
        // ---------------------------------------------------------------
        public object GetUserVulnerable(string username)
        {
            // ❌ BAD: user input is directly embedded in the SQL string
            string query = "SELECT * FROM Users WHERE Username = '" + username + "'";

            using (var conn = new SqlConnection(_connectionString))
            using (var cmd  = new SqlCommand(query, conn))
            {
                conn.Open();
                return cmd.ExecuteScalar();
            }
        }

        // ---------------------------------------------------------------
        // VULNERABILITY 2: XSS via unencoded output
        // Attacker input: <script>alert('XSS')</script>
        // → script executes in every visitor's browser
        // ---------------------------------------------------------------
        public string RenderGreetingVulnerable(string username)
        {
            // ❌ BAD: raw user input written directly into HTML
            return "<h1>Welcome, " + username + "!</h1>";
        }

        // ---------------------------------------------------------------
        // VULNERABILITY 3: No input length check
        // Attacker sends 10,000-character username → potential buffer issues
        // ---------------------------------------------------------------
        public bool LoginVulnerable(string username, string password)
        {
            // ❌ BAD: no length/format validation, and string-concatenated query
            string query = "SELECT COUNT(1) FROM Users WHERE Username='" 
                           + username + "' AND Password='" + password + "'";

            using (var conn = new SqlConnection(_connectionString))
            using (var cmd  = new SqlCommand(query, conn))
            {
                conn.Open();
                return (int)cmd.ExecuteScalar() > 0;
            }
        }
    }
}
