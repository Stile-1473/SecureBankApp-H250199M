package securebank.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import securebank.MutableClock;
import securebank.exception.AccountNotFoundException;
import securebank.exception.AuthenticationException;
import securebank.repository.InMemoryAccountRepository;
import securebank.repository.InMemoryTransactionRepository;
import securebank.repository.InMemoryUserRepository;
import securebank.service.AccountService;
import securebank.service.AuthService;

class AuditLoggerTest {

    private static final String PW = "Kariba#Sunset47";

    private final MutableClock clock = new MutableClock(Instant.parse("2026-10-12T08:00:00Z"));
    private final Path logFile;
    private final AuditLogger audit;

    AuditLoggerTest() throws IOException {
        logFile = Files.createTempDirectory("audit-test").resolve("logs").resolve("audit.log");
        audit = AuditLogger.toFile(logFile, clock);
    }

    private List<String> lines() throws IOException {
        return Files.readAllLines(logFile, StandardCharsets.UTF_8);
    }

    @Test
    void writesOneLinePerEvent() throws IOException {
        audit.log("LOGIN_SUCCESS", "ghost1473", null);
        audit.log("LOGIN_FAILED", "ghost1473", "reason=wrong_password");
        assertEquals(List.of(
                "2026-10-12T08:00:00Z LOGIN_SUCCESS user=ghost1473",
                "2026-10-12T08:00:00Z LOGIN_FAILED user=ghost1473 reason=wrong_password"), lines());
    }

    @Test
    void logInjectionCannotForgeExtraLines() throws IOException {
        audit.log("LOGIN_FAILED", "x\n2026-10-12T08:00:00Z LOGIN_SUCCESS user=admin", null);
        List<String> lines = lines();
        assertEquals(1, lines.size());
        assertFalse(lines.get(0).contains("\n"));
        assertTrue(lines.get(0).startsWith("2026-10-12T08:00:00Z LOGIN_FAILED user=x_2026"));
    }

    @Test
    void longAndControlInputIsSanitised() {
        assertEquals("a_b_c", AuditLogger.sanitise("a\tb\rc"));
        assertEquals("-", AuditLogger.sanitise(null));
        assertTrue(AuditLogger.sanitise("x".repeat(500)).length() < 80);
        assertEquals("ghost_admin", AuditLogger.sanitise("ghost|admin"));
    }

    @Test
    void masksAccountNumbers() {
        assertEquals("******1234", AuditLogger.mask("6200001234"));
        assertEquals("****", AuditLogger.mask("12"));
    }

    @Test
    void disabledLoggerWritesNothing() {
        AuditLogger.disabled().log("LOGIN_SUCCESS", "ghost1473", null);
        assertFalse(Files.exists(logFile));
    }

    @Test
    void servicesRecordSecurityEventsWithoutSecrets() throws IOException {
        AuthService auth = new AuthService(new InMemoryUserRepository(), TestHashers.fast(),
                new PasswordPolicy(), new LoginThrottler(), clock, audit);
        AccountService bank = new AccountService(new InMemoryAccountRepository(),
                new InMemoryTransactionRepository(), auth, new AccountNumberGenerator(), clock, audit);

        auth.register("ghost1473", PW.toCharArray());
        auth.register("alice01", PW.toCharArray());
        try {
            auth.login("ghost1473", "Wrong#Pass9999".toCharArray());
        } catch (AuthenticationException expected) {
            // expected
        }
        Session ghost = auth.login("ghost1473", PW.toCharArray());
        Session alice = auth.login("alice01", PW.toCharArray());
        String acc = bank.openAccount(ghost).getAccountNumber();
        bank.deposit(ghost, acc, new BigDecimal("50.00"));
        try {
            bank.getBalance(alice, acc); // alice probing ghost's account
        } catch (AccountNotFoundException expected) {
            // expected
        }

        String log = String.join("\n", lines());
        assertTrue(log.contains("USER_REGISTERED user=ghost1473"));
        assertTrue(log.contains("LOGIN_FAILED user=ghost1473 reason=wrong_password attempts=1"));
        assertTrue(log.contains("LOGIN_SUCCESS user=ghost1473"));
        assertTrue(log.contains("DEPOSIT user=ghost1473 account=" + AuditLogger.mask(acc) + " amount=50.00"));
        assertTrue(log.contains("ACCESS_DENIED user=alice01 account=" + AuditLogger.mask(acc)));
        assertFalse(log.contains(PW));          // no passwords
        assertFalse(log.contains(acc));         // no full account numbers
        assertFalse(log.contains("pbkdf2"));    // no hashes
    }
}
