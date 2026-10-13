package securebank.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import securebank.exception.ValidationException;
import securebank.security.PasswordHash;

class UserTest {

    private static final PasswordHash HASH = new PasswordHash(new byte[16], new byte[32], 1);
    private static final Instant NOW = Instant.parse("2026-10-05T08:00:00Z");

    @Test
    void lockoutExpires() {
        User user = new User("ghost1473", HASH, NOW);
        user.lockUntil(NOW.plus(Duration.ofMinutes(5)));
        assertTrue(user.isLockedAt(NOW.plusSeconds(60)));
        assertFalse(user.isLockedAt(NOW.plus(Duration.ofMinutes(6))));
    }

    @Test
    void successfulLoginResetsFailures() {
        User user = new User("ghost1473", HASH, NOW);
        user.recordFailedLogin();
        user.recordFailedLogin();
        user.lockUntil(NOW.plusSeconds(60));
        user.resetLoginFailures();
        assertEquals(0, user.getFailedAttempts());
        assertFalse(user.isLockedAt(NOW));
    }

    @Test
    void corruptStoredStateIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> new User("ghost1473", HASH, NOW, -1, null));
        assertThrows(ValidationException.class, () -> new User("bad|name", HASH, NOW));
    }

    @Test
    void toStringHidesCredential() {
        assertEquals("User[ghost1473]", new User("Ghost1473", HASH, NOW).toString());
    }
}
