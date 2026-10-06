package securebank.security;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/*
 - Password strength rules, based on NIST SP 800-63B (length + blocklist) with an
 - added character-variety rule
 0-
 -<p>Works directly on {@code char[]} so the password is never copied into an
 - immutable {@code String} that would linger in memory.
 */
public final class PasswordPolicy {

    public static final int MIN_LENGTH = 12;
    // Upper bound stops someone submitting a huge input to the server and causing a denial-of-service
    public static final int MAX_LENGTH = 128;
    private static final int MIN_CHARACTER_CLASSES = 3;
    private static final int MAX_RUN = 3;


    // Common base words: any password containing one of these is rejected

    private static final Set<String> BLOCKED_WORDS = Set.of(
            "password", "passw0rd", "qwerty", "letmein", "welcome", "admin", "iloveyou",
            "monkey", "dragon", "football", "abc123", "123456", "654321", "111111",
            "bank", "securebank", "zimbabwe", "harare", "changeme", "secret");


    public List<String> check(char[] password, String username) {
        List<String> problems = new ArrayList<>();
        if (password == null || password.length < MIN_LENGTH) {
            problems.add("Password must be at least " + MIN_LENGTH + " characters");
            if (password == null) {
                return problems;
            }
        }
        if (password.length > MAX_LENGTH) {
            problems.add("Password must be at most " + MAX_LENGTH + " characters");
        }
        if (countCharacterClasses(password) < MIN_CHARACTER_CLASSES) {
            problems.add("Password must use at least 3 of: lower case, upper case, digits, symbols");
        }
        if (hasWhitespaceOrControl(password)) {
            problems.add("Password must not contain spaces or control characters");
        }
        if (hasLongRunOrSequence(password)) {
            problems.add("Password must not contain repeated or sequential characters like 'aaaa' or '1234'");
        }
        char[] lower = toLowerCase(password);
        try {
            for (String word : BLOCKED_WORDS) {
                if (contains(lower, word)) {
                    problems.add("Password contains a common word or pattern that is easy to guess");
                    break;
                }
            }
            if (username != null && !username.isEmpty()
                    && contains(lower, username.toLowerCase(Locale.ROOT))) {
                problems.add("Password must not contain your username");
            }
        } finally {
            java.util.Arrays.fill(lower, '\0');
        }
        return problems;
    }

    private static int countCharacterClasses(char[] pw) {
        boolean lower = false;
        boolean upper = false;
        boolean digit = false;
        boolean symbol = false;
        for (char c : pw) {
            if (Character.isLowerCase(c)) {
                lower = true;
            } else if (Character.isUpperCase(c)) {
                upper = true;
            } else if (Character.isDigit(c)) {
                digit = true;
            } else {
                symbol = true;
            }
        }
        return (lower ? 1 : 0) + (upper ? 1 : 0) + (digit ? 1 : 0) + (symbol ? 1 : 0);
    }

    private static boolean hasWhitespaceOrControl(char[] pw) {
        for (char c : pw) {
            if (Character.isWhitespace(c) || Character.isISOControl(c)) {
                return true;
            }
        }
        return false;
    }

    /** Detects runs like "aaaa" and sequences like "1234", "abcd" or "dcba" (length > MAX_RUN). */
    private static boolean hasLongRunOrSequence(char[] pw) {
        int same = 1;
        int up = 1;
        int down = 1;
        for (int i = 1; i < pw.length; i++) {
            char prev = Character.toLowerCase(pw[i - 1]);
            char cur = Character.toLowerCase(pw[i]);
            same = (cur == prev) ? same + 1 : 1;
            up = (cur == prev + 1) ? up + 1 : 1;
            down = (cur == prev - 1) ? down + 1 : 1;
            if (same > MAX_RUN || up > MAX_RUN || down > MAX_RUN) {
                return true;
            }
        }
        return false;
    }

    private static char[] toLowerCase(char[] pw) {
        char[] out = new char[pw.length];
        for (int i = 0; i < pw.length; i++) {
            out[i] = Character.toLowerCase(pw[i]);
        }
        return out;
    }

    private static boolean contains(char[] haystack, String needle) {
        int n = needle.length();
        for (int i = 0; i + n <= haystack.length; i++) {
            int j = 0;
            while (j < n && haystack[i + j] == needle.charAt(j)) {
                j++;
            }
            if (j == n) {
                return true;
            }
        }
        return false;
    }
}