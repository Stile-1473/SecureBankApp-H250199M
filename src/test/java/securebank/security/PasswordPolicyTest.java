package securebank.security;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class PasswordPolicyTest {

    private final PasswordPolicy policy = new PasswordPolicy();

    private List<String> check(String pw) {
        return policy.check(pw.toCharArray(), "ghost1473");
    }

    private static boolean mentions(List<String> problems, String text) {
        return problems.stream().anyMatch(p -> p.contains(text));
    }

    @Test
    void strongPasswordPasses() {
        assertTrue(check("Kariba#Sunset47").isEmpty());
    }

    @Test
    void shortPasswordFails() {
        assertTrue(mentions(check("Ab1!x"), "at least"));
    }

    @Test
    void tooLongPasswordFails() {
        assertTrue(mentions(check("Aa1!".repeat(33)), "at most"));
    }

    @Test
    void commonWordFails() {
        assertTrue(mentions(check("MyPassword!2026x"), "common word"));
    }

    @Test
    void passwordContainingUsernameFails() {
        assertTrue(mentions(check("Xghost1473!!Q"), "username"));
    }

    @Test
    void sequenceFails() {
        assertTrue(mentions(check("Kariba#1234xyz"), "sequential"));
    }

    @Test
    void repeatedCharactersFail() {
        assertTrue(mentions(check("Kariba#aaaa77"), "repeated"));
    }

    @Test
    void lowVarietyFails() {
        assertTrue(mentions(check("karibasunsetlake"), "at least 3 of"));
    }

    @Test
    void whitespaceFails() {
        assertTrue(mentions(check("Kariba Sunset47"), "spaces"));
    }

    @Test
    void reportsAllProblemsAtOnce() {
        assertTrue(check("password").size() >= 3);
    }

    @Test
    void doesNotModifyCallersArray() {
        char[] pw = "Kariba#Sunset47".toCharArray();
        policy.check(pw, "ghost1473");
        assertFalse(new String(pw).contains("\0"));
    }
}
