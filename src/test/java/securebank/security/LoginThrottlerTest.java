package securebank.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import securebank.model.User;

class LoginThrottlerTest {

    private static final Instant NOW = Instant.parse("2026-10-06T08:00:00Z");
    private final LoginThrottler throttler = new LoginThrottler();

    private static User newUser() {
        return new User("ghost1473", new PasswordHash(new byte[16], new byte[32], 1), NOW);
    }

    @Test
    void fourFailuresDoNotLock() {
        User user = newUser();
        for (int i = 0; i < 4; i++) {
            throttler.onFailure(user, NOW);
        }
        assertFalse(user.isLockedAt(NOW));
    }

    @Test
    void fifthFailureLocksForOneMinute() {
        User user = newUser();
        for (int i = 0; i < 5; i++) {
            throttler.onFailure(user, NOW);
        }
        assertTrue(user.isLockedAt(NOW.plusSeconds(59)));
        assertFalse(user.isLockedAt(NOW.plusSeconds(61)));
    }

    @Test
    void lockTimeDoublesAndIsCapped() {
        assertEquals(Duration.ofMinutes(1), LoginThrottler.lockDurationFor(5));
        assertEquals(Duration.ofMinutes(2), LoginThrottler.lockDurationFor(6));
        assertEquals(Duration.ofMinutes(4), LoginThrottler.lockDurationFor(7));
        assertEquals(Duration.ofMinutes(8), LoginThrottler.lockDurationFor(8));
        assertEquals(Duration.ofMinutes(15), LoginThrottler.lockDurationFor(9));
        assertEquals(Duration.ofMinutes(15), LoginThrottler.lockDurationFor(1_000));
    }

    @Test
    void successClearsEverything() {
        User user = newUser();
        for (int i = 0; i < 5; i++) {
            throttler.onFailure(user, NOW);
        }
        throttler.onSuccess(user);
        assertEquals(0, user.getFailedAttempts());
        assertFalse(user.isLockedAt(NOW));
    }
}
