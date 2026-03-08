// SafeVault/Helpers/ValidationHelpers.cs
// Provides input sanitization and XSS detection utilities.
// All inputs MUST be validated server-side regardless of client-side checks.

using System;
using System.Linq;
using System.Text.RegularExpressions;
using System.Web; // HttpUtility for HtmlEncode

namespace SafeVault.Helpers
{
    public static class ValidationHelpers
    {
        // Only allow letters, digits, and underscores for usernames
        private static readonly Regex UsernamePattern = new Regex(@"^[a-zA-Z0-9_]{3,100}$", RegexOptions.Compiled);

        // Standard email pattern
        private static readonly Regex EmailPattern = new Regex(
            @"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        // XSS attack patterns to detect
        private static readonly string[] XssPatterns = new[]
        {
            "<script", "</script>", "<iframe", "javascript:",
            "onerror=", "onload=", "onclick=", "eval(",
            "document.cookie", "alert(", "prompt("
        };

        /// <summary>
        /// Validates a username: alphanumeric + underscore, 3–100 chars, no XSS.
        /// </summary>
        public static bool IsValidUsername(string input)
        {
            if (string.IsNullOrWhiteSpace(input)) return false;
            return UsernamePattern.IsMatch(input) && !ContainsXSS(input);
        }

        /// <summary>
        /// Validates an email address: standard format, max 100 chars, no XSS.
        /// </summary>
        public static bool IsValidEmail(string input)
        {
            if (string.IsNullOrWhiteSpace(input)) return false;
            if (input.Length > 100) return false;
            return EmailPattern.IsMatch(input) && !ContainsXSS(input);
        }

        /// <summary>
        /// Generic validator: allows letters, digits, and specified special characters.
        /// </summary>
        public static bool IsValidInput(string input, string allowedSpecialCharacters = "")
        {
            if (string.IsNullOrEmpty(input)) return false;
            var validExtras = allowedSpecialCharacters.ToHashSet();
            return input.All(c => char.IsLetterOrDigit(c) || validExtras.Contains(c))
                   && !ContainsXSS(input);
        }

        /// <summary>
        /// Detects common XSS attack patterns in a string (case-insensitive).
        /// Returns true if a malicious pattern is found.
        /// </summary>
        public static bool ContainsXSS(string input)
        {
            if (string.IsNullOrEmpty(input)) return false;
            var lower = input.ToLowerInvariant();
            return XssPatterns.Any(pattern => lower.Contains(pattern));
        }

        /// <summary>
        /// HTML-encodes a string for safe output in web pages.
        /// Use this when rendering any user-supplied value into HTML.
        /// </summary>
        public static string SanitizeForOutput(string input)
        {
            if (string.IsNullOrEmpty(input)) return string.Empty;
            return HttpUtility.HtmlEncode(input);
        }
    }
}
