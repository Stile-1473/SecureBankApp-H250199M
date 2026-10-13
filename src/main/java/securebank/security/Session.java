package securebank.security;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import securebank.exception.SessionExpiredException;

/*
 * Represents a logged-in user's session
 * The session expires after 5 minutes of inactivity, after 30 minutes in total or when the user logs out
 * This helps protect the account if someone leaves a terminal unlocked
 */
public final class Session {

    public static final Duration IDLE_TIMEOUT = Duration.ofMinutes(5);
    public static final Duration MAX_LIFETIME = Duration.ofMinutes(30);

    private final String username;
    private final Instant startedAt;
    private Instant lastActivity;
    private boolean active = true;

    public Session(String username, Instant startedAt) {
        this.username = Objects.requireNonNull(username, "username");
        this.startedAt = Objects.requireNonNull(startedAt, "startedAt");
        this.lastActivity = startedAt;
    }

    public String getUsername() {
        return username;
    }

    public boolean isValidAt(Instant now) {
        return active
                && now.isBefore(lastActivity.plus(IDLE_TIMEOUT))
                && now.isBefore(startedAt.plus(MAX_LIFETIME));
    }

    /*
     * Call this before every action
     * Throws an exception if the session has expired, ootherwise updates the last activity time
     */
    public void touch(Instant now) {
        if (!isValidAt(now)) {
            active = false;
            throw new SessionExpiredException();
        }
        lastActivity = now;
    }

    public void invalidate() {
        active = false;
    }
}