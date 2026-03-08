// SafeVault/Tests/TestInputValidation.cs
// NUnit tests that simulate real SQL injection and XSS attack payloads.
// All tests should PASS (i.e., attacks are correctly rejected).

using NUnit.Framework;
using SafeVault.Helpers;
using SafeVault.Data;

namespace SafeVault.Tests
{
    [TestFixture]
    public class TestInputValidation
    {
        // =====================================================================
        // SQL INJECTION TESTS
        // Verify that malicious SQL payloads are rejected by validation before
        // they can ever reach the database layer.
        // =====================================================================

        [Test]
        [TestCase("' OR '1'='1",         TestName = "SQLi_Classic_OR")]
        [TestCase("'; DROP TABLE Users;--", TestName = "SQLi_Drop_Table")]
        [TestCase("admin'--",             TestName = "SQLi_Comment_Bypass")]
        [TestCase("1; SELECT * FROM Users", TestName = "SQLi_Stacked_Query")]
        [TestCase("' UNION SELECT null,username,password FROM Users--", TestName = "SQLi_Union_Select")]
        public void TestForSQLInjection_Username_IsRejected(string maliciousInput)
        {
            // ValidationHelpers must reject any input containing SQL control chars
            bool result = ValidationHelpers.IsValidUsername(maliciousInput);

            Assert.IsFalse(result,
                $"SQL injection payload was not blocked: '{maliciousInput}'");
        }

        [Test]
        [TestCase("validuser",   TestName = "SQLi_Clean_Username_Accepted")]
        [TestCase("user_123",    TestName = "SQLi_Underscore_Username_Accepted")]
        [TestCase("Alice",       TestName = "SQLi_Alpha_Username_Accepted")]
        public void TestForSQLInjection_CleanUsername_IsAccepted(string safeInput)
        {
            bool result = ValidationHelpers.IsValidUsername(safeInput);

            Assert.IsTrue(result,
                $"Valid username was incorrectly rejected: '{safeInput}'");
        }

        [Test]
        [TestCase("' OR 1=1--",                    TestName = "SQLi_Email_OR_Bypass")]
        [TestCase("test@test.com; DROP TABLE Users", TestName = "SQLi_Email_Drop")]
        public void TestForSQLInjection_Email_IsRejected(string maliciousEmail)
        {
            bool result = ValidationHelpers.IsValidEmail(maliciousEmail);

            Assert.IsFalse(result,
                $"SQL injection in email was not blocked: '{maliciousEmail}'");
        }

        [Test]
        public void TestForSQLInjection_ValidEmail_IsAccepted()
        {
            bool result = ValidationHelpers.IsValidEmail("alice@example.com");
            Assert.IsTrue(result, "Valid email was incorrectly rejected.");
        }

        // =====================================================================
        // XSS TESTS
        // Verify that script injection and HTML injection payloads are detected.
        // =====================================================================

        [Test]
        [TestCase("<script>alert('XSS')</script>",              TestName = "XSS_Script_Tag")]
        [TestCase("<Script>alert(1)</Script>",                   TestName = "XSS_Script_MixedCase")]
        [TestCase("<iframe src='javascript:alert(1)'>",          TestName = "XSS_IFrame_Javascript")]
        [TestCase("javascript:alert(document.cookie)",           TestName = "XSS_Javascript_Protocol")]
        [TestCase("<img src=x onerror=alert('XSS')>",           TestName = "XSS_Img_OnError")]
        [TestCase("<body onload=alert('XSS')>",                  TestName = "XSS_Body_OnLoad")]
        [TestCase("eval(atob('YWxlcnQoMSk='))",                 TestName = "XSS_Eval_Base64")]
        [TestCase("<div onclick=\"document.cookie\">click me</div>", TestName = "XSS_OnClick_Cookie")]
        public void TestForXSS_MaliciousInput_IsDetected(string maliciousInput)
        {
            bool containsXss = ValidationHelpers.ContainsXSS(maliciousInput);

            Assert.IsTrue(containsXss,
                $"XSS payload was NOT detected (vulnerability!): '{maliciousInput}'");
        }

        [Test]
        [TestCase("<script>alert('XSS')</script>",    TestName = "XSS_Username_ScriptTag_Rejected")]
        [TestCase("<img onerror=alert(1) src=x>",     TestName = "XSS_Username_ImgTag_Rejected")]
        public void TestForXSS_Username_IsRejected(string xssPayload)
        {
            bool result = ValidationHelpers.IsValidUsername(xssPayload);

            Assert.IsFalse(result,
                $"XSS payload in username was not blocked: '{xssPayload}'");
        }

        [Test]
        [TestCase("normaluser",         TestName = "XSS_Clean_Username_Accepted")]
        [TestCase("safe_input_123",     TestName = "XSS_Clean_AlphaNumeric_Accepted")]
        public void TestForXSS_CleanInput_IsAccepted(string safeInput)
        {
            bool containsXss = ValidationHelpers.ContainsXSS(safeInput);

            Assert.IsFalse(containsXss,
                $"Clean input was falsely flagged as XSS: '{safeInput}'");
        }

        // =====================================================================
        // OUTPUT ENCODING TESTS
        // Verify SanitizeForOutput() HTML-encodes dangerous characters.
        // =====================================================================

        [Test]
        public void TestSanitizeForOutput_EncodesScriptTag()
        {
            string input    = "<script>alert('XSS')</script>";
            string result   = ValidationHelpers.SanitizeForOutput(input);

            StringAssert.DoesNotContain("<script>", result,
                "Raw <script> tag present in output — encoding failed.");
            StringAssert.Contains("&lt;script&gt;", result,
                "Expected HTML-encoded script tag in output.");
        }

        [Test]
        public void TestSanitizeForOutput_EncodesAmpersandAndQuotes()
        {
            string input  = "Rock & Roll \"Quotes\" O'Brien";
            string result = ValidationHelpers.SanitizeForOutput(input);

            StringAssert.Contains("&amp;",  result, "Ampersand not encoded.");
            StringAssert.Contains("&quot;", result, "Double quote not encoded.");
        }

        [Test]
        public void TestSanitizeForOutput_EmptyInput_ReturnsEmpty()
        {
            Assert.AreEqual(string.Empty, ValidationHelpers.SanitizeForOutput(string.Empty));
            Assert.AreEqual(string.Empty, ValidationHelpers.SanitizeForOutput(null));
        }

        // =====================================================================
        // BOUNDARY / EDGE CASE TESTS
        // =====================================================================

        [Test]
        public void TestUsername_TooShort_IsRejected()
        {
            Assert.IsFalse(ValidationHelpers.IsValidUsername("ab"),
                "Username shorter than 3 chars should be rejected.");
        }

        [Test]
        public void TestUsername_TooLong_IsRejected()
        {
            string longInput = new string('a', 101);
            Assert.IsFalse(ValidationHelpers.IsValidUsername(longInput),
                "Username longer than 100 chars should be rejected.");
        }

        [Test]
        public void TestEmail_TooLong_IsRejected()
        {
            string longEmail = new string('a', 95) + "@b.com";
            Assert.IsFalse(ValidationHelpers.IsValidEmail(longEmail),
                "Email longer than 100 chars should be rejected.");
        }

        [Test]
        public void TestNullInput_IsRejected()
        {
            Assert.IsFalse(ValidationHelpers.IsValidUsername(null));
            Assert.IsFalse(ValidationHelpers.IsValidEmail(null));
        }
    }
}
