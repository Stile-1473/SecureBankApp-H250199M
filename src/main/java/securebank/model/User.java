package securebank.model;

import java.time.Instant;
import java.util.Objects;
import securebank.security.InputValidator;
import securebank.security.PasswordHash;


public final class User {

    private final String username;
    private final Instant createdAt;
    private PasswordHash passwordHash;
    private int failedAttempts;
    private Instant lockedUntil; // null when not locked

    /* Creates a new user */
    public User(String username, PasswordHash passwordHash, Instant createdAt) {
        this(username, passwordHash, createdAt, 0, null);
    }

    // Rebuilds a user loaded from storage; validates everything trusts nothing
    public User(String username, PasswordHash passwordHash, Instant createdAt,
                int failedAttempts, Instant lockedUntil) {
        this.username = InputValidator.username(username);
        this.passwordHash = Objects.requireNonNull(passwordHash, "passwordHash");
        this.createdAt = Objects.requireNonNull(createdAt, "createdAt");
        if (failedAttempts < 0) {
            throw new IllegalArgumentException("failedAttempts cannot be negative");
        }
        this.failedAttempts = failedAttempts;
        this.lockedUntil = lockedUntil;
    }

    public String getUsername() {
        return username;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public PasswordHash getPasswordHash() {
        return passwordHash; // immutable safe to share
    }

    public int getFailedAttempts() {
        return failedAttempts;
    }

    public Instant getLockedUntil() {
        return lockedUntil;
    }

    public boolean isLockedAt(Instant now) {
        return lockedUntil != null && now.isBefore(lockedUntil);
    }

    // Records a failed login and returns the new count
    public int recordFailedLogin() {
        failedAttempts++;
        return failedAttempts;
    }

    public void lockUntil(Instant until) {
        this.lockedUntil = Objects.requireNonNull(until, "until");
    }

    // Called after a successful login
    public void resetLoginFailures() {
        failedAttempts = 0;
        lockedUntil = null;
    }

    // Replaces the credential e.g. on password change or work-factor upgrade
    public void changePasswordHash(PasswordHash newHash) {
        this.passwordHash = Objects.requireNonNull(newHash, "newHash");
    }

    @Override
    public String toString() {
        return "User[" + username + "]"; // never include the credential
    }
}