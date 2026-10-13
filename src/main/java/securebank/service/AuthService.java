package securebank.service;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import securebank.exception.AuthenticationException;
import securebank.exception.ValidationException;
import securebank.model.User;
import securebank.repository.UserRepository;
import securebank.security.AuditLogger;
import securebank.security.InputValidator;
import securebank.security.LoginThrottler;
import securebank.security.PasswordHasher;
import securebank.security.PasswordPolicy;
import securebank.security.Session;

/*
 * Handles user registration and login
 * Login errors use the same message to avoid revealing whether a username
 * exists, the password is incorrect or the account has been locked
 */
public final class AuthService {

    static final String LOGIN_FAILED =
            "Login failed. Check your username and password, or try again later.";
    static final String REAUTH_FAILED = "Password confirmation failed.";

    private final UserRepository users;
    private final PasswordHasher hasher;
    private final PasswordPolicy policy;
    private final LoginThrottler throttler;
    private final Clock clock;
    private final AuditLogger audit;

    // Used when audit logging is not needed such as in unit tests
    public AuthService(UserRepository users, PasswordHasher hasher, PasswordPolicy policy,
                       LoginThrottler throttler, Clock clock) {
        this(users, hasher, policy, throttler, clock, AuditLogger.disabled());
    }

    public AuthService(UserRepository users, PasswordHasher hasher, PasswordPolicy policy,
                       LoginThrottler throttler, Clock clock, AuditLogger audit) {
        this.audit = Objects.requireNonNull(audit, "audit");
        this.users = Objects.requireNonNull(users, "users");
        this.hasher = Objects.requireNonNull(hasher, "hasher");
        this.policy = Objects.requireNonNull(policy, "policy");
        this.throttler = Objects.requireNonNull(throttler, "throttler");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /*
     * Registers a new user after checking that the username and password
     * meet the required rules. The caller is responsible for clearing
     * the password from memory
     */
    public User register(String rawUsername, char[] password) {
        String username = InputValidator.username(rawUsername);
        List<String> problems = policy.check(password, username);
        if (!problems.isEmpty()) {
            throw new ValidationException(problems);
        }
        User user = new User(username, hasher.hash(password), clock.instant());
        if (!users.add(user)) {
            throw new ValidationException("That username is not available");
        }
        audit.log("USER_REGISTERED", username, null);
        return user;
    }
    /*
     * Logs a user in and creates a session if the credentials are correct
     * All login failures use the same general error message for security
     */

    public Session login(String rawUsername, char[] password) {
        if (password == null || password.length == 0) {
            audit.log("LOGIN_FAILED", rawUsername, "reason=empty_password");
            throw new AuthenticationException(LOGIN_FAILED);
        }

        String username;
        try {
            username = InputValidator.username(rawUsername);
        } catch (ValidationException e) {
            // Check the password anyway so invalid usernames take a similar
           // amount of time to process as normal login attempt
            hasher.dummyVerify(password);
            audit.log("LOGIN_FAILED", rawUsername, "reason=invalid_username");
            throw new AuthenticationException(LOGIN_FAILED);
        }

        Optional<User> found = users.findByUsername(username);
        if (found.isEmpty()) {
            hasher.dummyVerify(password);
            audit.log("LOGIN_FAILED", username, "reason=unknown_user");
            throw new AuthenticationException(LOGIN_FAILED);
        }

        User user = found.get();
        Instant now = clock.instant();

        if (user.isLockedAt(now)) {
            // A locked account cannot log in so there is no need to check
            // the actual password. A dummy check helps keep the timing similar
            hasher.dummyVerify(password);
            audit.log("LOGIN_BLOCKED", username, "reason=account_locked");
            throw new AuthenticationException(LOGIN_FAILED);
        }

        if (!hasher.verify(password, user.getPasswordHash())) {
            throttler.onFailure(user, now);
            users.update(user);
            audit.log("LOGIN_FAILED", username, "reason=wrong_password attempts=" + user.getFailedAttempts());
            if (user.isLockedAt(now)) {
                audit.log("ACCOUNT_LOCKED", username, "until=" + user.getLockedUntil());
            }
            throw new AuthenticationException(LOGIN_FAILED);
        }

        throttler.onSuccess(user);
        if (hasher.needsRehash(user.getPasswordHash())) {
            // Update the password hash if it uses older hashing settings
            user.changePasswordHash(hasher.hash(password));
        }
        users.update(user);
        audit.log("LOGIN_SUCCESS", username, null);
        return new Session(user.getUsername(), now);
    }

    /*
     * Checks the password again before allowing sensitive actions,
     * such as a large withdrawal. Failed attempts count towards the
     * account lockout limit. If the account becomes locked, the
     * current session is ended as well
     */
    public void reauthenticate(Session session, char[] password) {
        Instant now = clock.instant();
        session.touch(now);
        User user = users.findByUsername(session.getUsername())
                .orElseThrow(() -> new AuthenticationException(LOGIN_FAILED));

        if (user.isLockedAt(now)) {
            session.invalidate();
            audit.log("REAUTH_BLOCKED", user.getUsername(), "reason=account_locked");
            throw new AuthenticationException(REAUTH_FAILED);
        }

        boolean correct = password != null && password.length > 0
                && hasher.verify(password, user.getPasswordHash());
        if (!correct) {
            throttler.onFailure(user, now);
            users.update(user);
            audit.log("REAUTH_FAILED", user.getUsername(), "attempts=" + user.getFailedAttempts());
            if (user.isLockedAt(now)) {
                session.invalidate();
                audit.log("ACCOUNT_LOCKED", user.getUsername(), "until=" + user.getLockedUntil() + " session=ended");
            }
            throw new AuthenticationException(REAUTH_FAILED);
        }

        throttler.onSuccess(user);
        users.update(user);
    }
}
