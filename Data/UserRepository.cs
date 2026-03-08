// SafeVault/Data/UserRepository.cs
// All database interactions use parameterized queries to prevent SQL injection.
// Never concatenate user input directly into SQL strings.

using System;
using System.Data;
using System.Data.SqlClient;
using SafeVault.Helpers;

namespace SafeVault.Data
{
    public class UserRepository
    {
        // Connection string should come from encrypted config / environment variable
        private readonly string _connectionString;

        public UserRepository(string connectionString)
        {
            _connectionString = connectionString
                ?? throw new ArgumentNullException(nameof(connectionString));
        }

        /// <summary>
        /// Inserts a new user after validating inputs.
        /// Uses parameterized query — no raw string interpolation.
        /// </summary>
        public bool CreateUser(string username, string email)
        {
            // Server-side validation (mirrors client-side checks)
            if (!ValidationHelpers.IsValidUsername(username))
                throw new ArgumentException("Invalid username format.", nameof(username));

            if (!ValidationHelpers.IsValidEmail(email))
                throw new ArgumentException("Invalid email format.", nameof(email));

            const string query = @"
                INSERT INTO Users (Username, Email)
                VALUES (@Username, @Email)";

            using (var connection = new SqlConnection(_connectionString))
            using (var command = new SqlCommand(query, connection))
            {
                // Parameters are bound separately — user data never touches the SQL string
                command.Parameters.Add("@Username", SqlDbType.NVarChar, 100).Value = username;
                command.Parameters.Add("@Email",    SqlDbType.NVarChar, 100).Value = email;

                connection.Open();
                int rowsAffected = command.ExecuteNonQuery();
                return rowsAffected == 1;
            }
        }

        /// <summary>
        /// Retrieves a user by username using a parameterized SELECT query.
        /// </summary>
        public DataRow GetUserByUsername(string username)
        {
            if (!ValidationHelpers.IsValidUsername(username))
                throw new ArgumentException("Invalid username format.", nameof(username));

            const string query = @"
                SELECT UserID, Username, Email
                FROM   Users
                WHERE  Username = @Username";

            using (var connection = new SqlConnection(_connectionString))
            using (var command = new SqlCommand(query, connection))
            {
                command.Parameters.Add("@Username", SqlDbType.NVarChar, 100).Value = username;

                var adapter = new SqlDataAdapter(command);
                var table = new DataTable();
                adapter.Fill(table);

                return table.Rows.Count > 0 ? table.Rows[0] : null;
            }
        }

        /// <summary>
        /// Secure login: validates credentials with a parameterized query.
        /// NOTE: In production, store password hashes (bcrypt/Argon2), not plaintext.
        /// </summary>
        public bool LoginUser(string username, string password)
        {
            // Allow a limited set of special characters in passwords
            const string allowedPasswordChars = "!@#$%^&*?";
            if (!ValidationHelpers.IsValidInput(username) ||
                !ValidationHelpers.IsValidInput(password, allowedPasswordChars))
                return false;

            const string query = @"
                SELECT COUNT(1)
                FROM   Users
                WHERE  Username = @Username
                AND    PasswordHash = @PasswordHash";

            using (var connection = new SqlConnection(_connectionString))
            using (var command = new SqlCommand(query, connection))
            {
                command.Parameters.Add("@Username",     SqlDbType.NVarChar, 100).Value = username;
                // Hash the password before comparing (example uses placeholder hash call)
                command.Parameters.Add("@PasswordHash", SqlDbType.NVarChar, 256).Value = HashPassword(password);

                connection.Open();
                int count = (int)command.ExecuteScalar();
                return count > 0;
            }
        }

        // Placeholder — replace with BCrypt.Net or ASP.NET Core PasswordHasher
        private static string HashPassword(string password)
        {
            using (var sha = System.Security.Cryptography.SHA256.Create())
            {
                var bytes = System.Text.Encoding.UTF8.GetBytes(password);
                var hash  = sha.ComputeHash(bytes);
                return Convert.ToBase64String(hash);
            }
        }
    }
}
