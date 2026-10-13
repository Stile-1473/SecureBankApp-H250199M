package securebank.security;

import java.time.Duration;
import java.time.Instant;
import securebank.model.User;

/*
 * Protects accounts against brute-force login attempts
 * After 5 failed logins the account gets locked, and each further failure increases the lock time
 * The lock grows from 1 to 2, 4, 8, then 15 minutes
 *
 * Locks are temporary on purpose, otherwise an attacker could keep customers out of their accounts
 * just by entering wrong passwords, causing a denial of service
 */
public final class LoginThrottler {

    public static final int MAX_ATTEMPTS = 5;
    static final Duration BASE_LOCK = Duration.ofMinutes(1);
    static final Duration MAX_LOCK = Duration.ofMinutes(15);

    /*Records a failed login and locks the user if they have reached the limit */
    public void onFailure(User user, Instant now) {
        int failures = user.recordFailedLogin();

        if (failures >= MAX_ATTEMPTS) {
            user.lockUntil(now.plus(lockDurationFor(failures)));
        }
    }

    /** Resets the failed login counter after a succesful login */
    public void onSuccess(User user) {
        user.resetLoginFailures();
    }

    static Duration lockDurationFor(int failures) {
        int extra = Math.min(failures - MAX_ATTEMPTS, 4); // Limit the shift so it doesnt overflow
        Duration lock = BASE_LOCK.multipliedBy(1L << extra);

        return lock.compareTo(MAX_LOCK) > 0 ? MAX_LOCK : lock;
    }
}