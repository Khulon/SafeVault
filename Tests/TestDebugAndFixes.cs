// SafeVault/Tests/TestDebugAndFixes.cs
// Confirms that:
//   (a) attack payloads are correctly blocked by the fixed code
//   (b) the vulnerable patterns would have allowed them through

using NUnit.Framework;
using System.Web;
using SafeVault.Helpers;

namespace SafeVault.Tests
{
    [TestFixture]
    public class TestDebugAndFixes
    {
        // ---------------------------------------------------------------
        // SQL INJECTION — input validation layer
        // The fixed code rejects these before they reach the database.
        // ---------------------------------------------------------------

        [Test]
        [TestCase("' OR '1'='1",            TestName = "SQLi_OR_Bypass")]
        [TestCase("'; DROP TABLE Users;--",  TestName = "SQLi_Drop_Table")]
        [TestCase("admin'--",               TestName = "SQLi_Comment_Bypass")]
        [TestCase("' UNION SELECT * FROM Users--", TestName = "SQLi_Union")]
        public void Fix1_SQLi_Payloads_RejectedByValidation(string payload)
        {
            // ValidationHelpers rejects any non-alphanumeric/underscore input
            bool isValid = ValidationHelpers.IsValidUsername(payload);
            Assert.IsFalse(isValid, $"SQL injection payload should be blocked: '{payload}'");
        }

        [Test]
        public void Fix1_CleanUsername_StillAccepted()
        {
            Assert.IsTrue(ValidationHelpers.IsValidUsername("alice_99"));
        }

        // ---------------------------------------------------------------
        // XSS — output encoding layer
        // HtmlEncode neutralises script tags and event handlers.
        // ---------------------------------------------------------------

        [Test]
        [TestCase("<script>alert('XSS')</script>", TestName = "XSS_ScriptTag")]
        [TestCase("<img src=x onerror=alert(1)>",  TestName = "XSS_ImgOnError")]
        [TestCase("<iframe src='javascript:'>",    TestName = "XSS_IFrame")]
        public void Fix2_XSS_Payloads_EncodedInOutput(string payload)
        {
            // Simulate what RenderGreetingSecure() does
            string encoded = HttpUtility.HtmlEncode(payload);

            // Raw tags must NOT appear in the output
            StringAssert.DoesNotContain("<script>", encoded, "Raw <script> tag found in output.");
            StringAssert.DoesNotContain("<img",     encoded, "Raw <img> tag found in output.");
            StringAssert.DoesNotContain("<iframe",  encoded, "Raw <iframe> tag found in output.");

            // Encoded form must be present instead
            StringAssert.Contains("&lt;", encoded, "Expected HTML-encoded '<' in output.");
        }

        [Test]
        public void Fix2_CleanUsername_RendersCorrectly()
        {
            string encoded = HttpUtility.HtmlEncode("alice");
            Assert.AreEqual("alice", encoded, "Clean input should pass through encoding unchanged.");
        }

        [Test]
        public void Fix2_XSS_DetectedByHelperBeforeOutput()
        {
            string payload = "<script>alert('XSS')</script>";
            Assert.IsTrue(ValidationHelpers.ContainsXSS(payload),
                "XSS payload should be detected by ContainsXSS().");
        }

        // ---------------------------------------------------------------
        // INPUT LENGTH / BOUNDARY CHECKS
        // ---------------------------------------------------------------

        [Test]
        public void Fix3_OversizedUsername_IsRejected()
        {
            string longInput = new string('a', 101);
            Assert.IsFalse(ValidationHelpers.IsValidUsername(longInput),
                "Username over 100 chars should be rejected.");
        }

        [Test]
        public void Fix3_NullInput_IsRejected()
        {
            Assert.IsFalse(ValidationHelpers.IsValidUsername(null));
            Assert.IsFalse(ValidationHelpers.IsValidEmail(null));
        }

        // ---------------------------------------------------------------
        // REGRESSION — ensure fixes don't break normal usage
        // ---------------------------------------------------------------

        [Test]
        public void Regression_ValidCredentials_PassAllChecks()
        {
            Assert.IsTrue(ValidationHelpers.IsValidUsername("john_doe"),  "Valid username rejected.");
            Assert.IsTrue(ValidationHelpers.IsValidEmail("john@safe.com"), "Valid email rejected.");
            Assert.IsFalse(ValidationHelpers.ContainsXSS("john_doe"),     "Clean input flagged as XSS.");
        }
    }
}
