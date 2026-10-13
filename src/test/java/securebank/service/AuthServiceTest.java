package securebank.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import securebank.MutableClock;
import securebank.exception.AuthenticationException;
import securebank.exception.ValidationException;
import securebank.model.User;
import securebank.repository.InMemoryUserRepository;
import securebank.security.LoginThrottler;
import securebank.security.PasswordHasher;
import securebank.security.PasswordPolicy;
import securebank.security.Session;
import securebank.security.TestHashers;

class AuthServiceTest {

    private static final String GOOD = "Kariba#Sunset47";

    private final MutableClock clock = new MutableClock(Instant.parse("2026-10-06T08:00:00Z"));
    private final InMemoryUserRepository users = new InMemoryUserRepository();
    private final AuthService auth = new AuthService(users, TestHashers.fast(),
            new PasswordPolicy(), new LoginThrottler(), clock);

    private String failWith(String username, String password) {
        return assertThrows(AuthenticationException.class,
                () -> auth.login(username, password.toCharArray())).getMessage();
    }

    @Test
    void registerThenLogin() {
        auth.register("Ghost1473", GOOD.toCharArray());
        Session session = auth.login("ghost1473", GOOD.toCharArray());
        assertEquals("ghost1473", session.getUsername());
    }

    @Test
    void duplicateUsernameIsRejectedRegardlessOfCase() {
        auth.register("ghost1473", GOOD.toCharArray());
        assertThrows(ValidationException.class, () -> auth.register("GHOST1473", GOOD.toCharArray()));
    }

    @Test
    void weakPasswordIsRejected() {
        assertThrows(ValidationException.class, () -> auth.register("ghost1473", "password".toCharArray()));
    }

    @Test
    void allFailuresLookTheSame() {
        auth.register("ghost1473", GOOD.toCharArray());
        String wrongPassword = failWith("ghost1473", "Wrong#Pass9999");
        String unknownUser = failWith("nobody99", GOOD);
        String badUsername = failWith("bad|name", GOOD);
        String emptyPassword = failWith("ghost1473", "");
        assertEquals(wrongPassword, unknownUser);
        assertEquals(wrongPassword, badUsername);
        assertEquals(wrongPassword, emptyPassword);
    }

    @Test
    void lockedAccountRejectsEvenCorrectPassword() {
        auth.register("ghost1473", GOOD.toCharArray());
        for (int i = 0; i < LoginThrottler.MAX_ATTEMPTS; i++) {
            failWith("ghost1473", "Wrong#Pass9999");
        }
        failWith("ghost1473", GOOD); // locked: correct password still refused

        clock.advance(Duration.ofMinutes(2)); // lock has expired
        Session session = auth.login("ghost1473", GOOD.toCharArray());
        assertEquals("ghost1473", session.getUsername());
    }

    @Test
    void successfulLoginResetsFailureCount() {
        auth.register("ghost1473", GOOD.toCharArray());
        failWith("ghost1473", "Wrong#Pass9999");
        failWith("ghost1473", "Wrong#Pass9999");
        auth.login("ghost1473", GOOD.toCharArray());
        assertEquals(0, users.findByUsername("ghost1473").orElseThrow().getFailedAttempts());
    }

    @Test
    void oldHashIsUpgradedOnLogin() {
        PasswordHasher old = TestHashers.withIterations(500);
        users.add(new User("ghost1473", old.hash(GOOD.toCharArray()), clock.instant()));

        auth.login("ghost1473", GOOD.toCharArray());

        int iterationsNow = users.findByUsername("ghost1473").orElseThrow()
                .getPasswordHash().iterations();
        assertTrue(iterationsNow > 500);
    }
}
