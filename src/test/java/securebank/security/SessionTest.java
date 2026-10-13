package securebank.security;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import securebank.exception.SessionExpiredException;

class SessionTest {

    private static final Instant START = Instant.parse("2026-10-06T08:00:00Z");

    @Test
    void expiresAfterIdleTimeout() {
        Session session = new Session("ghost1473", START);
        assertTrue(session.isValidAt(START.plus(Duration.ofMinutes(4))));
        assertThrows(SessionExpiredException.class,
                () -> session.touch(START.plus(Duration.ofMinutes(6))));
    }

    @Test
    void activityKeepsSessionAlive() {
        Session session = new Session("ghost1473", START);
        session.touch(START.plus(Duration.ofMinutes(4)));
        assertTrue(session.isValidAt(START.plus(Duration.ofMinutes(8))));
    }

    @Test
    void expiresAfterMaxLifetimeEvenIfActive() {
        Session session = new Session("ghost1473", START);
        for (int minute = 4; minute < 30; minute += 4) {
            session.touch(START.plus(Duration.ofMinutes(minute)));
        }
        assertFalse(session.isValidAt(START.plus(Duration.ofMinutes(31))));
    }

    @Test
    void logoutEndsSession() {
        Session session = new Session("ghost1473", START);
        session.invalidate();
        assertFalse(session.isValidAt(START));
    }
}
