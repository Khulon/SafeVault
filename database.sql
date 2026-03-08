-- SafeVault/database.sql
-- Secure database schema for SafeVault.
-- Follows OWASP guidelines: least privilege, no dynamic SQL, hashed passwords.

-- ============================================================
-- USERS TABLE
-- ============================================================
CREATE TABLE Users (
    UserID       INT          PRIMARY KEY AUTO_INCREMENT,
    Username     VARCHAR(100) NOT NULL UNIQUE,
    Email        VARCHAR(100) NOT NULL UNIQUE,
    -- Store bcrypt/Argon2 hash, never plaintext passwords
    PasswordHash VARCHAR(256) NOT NULL,
    CreatedAt    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    IsActive     TINYINT(1)   NOT NULL DEFAULT 1
);

-- Index for fast login lookups (Username is the login key)
CREATE INDEX idx_users_username ON Users(Username);

-- ============================================================
-- AUDIT LOG TABLE
-- Tracks login attempts to detect brute-force attacks.
-- ============================================================
CREATE TABLE AuditLog (
    LogID      INT          PRIMARY KEY AUTO_INCREMENT,
    UserID     INT,                          -- NULL for failed attempts on unknown users
    Action     VARCHAR(50)  NOT NULL,        -- e.g. 'LOGIN_SUCCESS', 'LOGIN_FAIL'
    IPAddress  VARCHAR(45)  NOT NULL,        -- Supports IPv6
    CreatedAt  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (UserID) REFERENCES Users(UserID) ON DELETE SET NULL
);

-- ============================================================
-- EXAMPLE PARAMETERIZED QUERY PATTERNS (for documentation)
-- All application queries must follow these patterns.
-- NEVER use string concatenation with user-supplied values.
-- ============================================================

-- Safe INSERT (C# uses SqlCommand with @-parameters):
-- INSERT INTO Users (Username, Email, PasswordHash)
-- VALUES (@Username, @Email, @PasswordHash)

-- Safe SELECT by username:
-- SELECT UserID, Username, Email
-- FROM   Users
-- WHERE  Username = @Username
-- AND    IsActive = 1

-- Safe login check (count avoids returning hash to application):
-- SELECT COUNT(1)
-- FROM   Users
-- WHERE  Username     = @Username
-- AND    PasswordHash = @PasswordHash
-- AND    IsActive     = 1

-- Safe audit log insert:
-- INSERT INTO AuditLog (UserID, Action, IPAddress)
-- VALUES (@UserID, @Action, @IPAddress)
