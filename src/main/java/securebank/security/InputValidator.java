package securebank.security;

import java.util.Locale;
import java.util.regex.Pattern;
import securebank.exception.ValidationException;

/**
 * Central whitelist validation. Every value typed by a user passes through here
 * before it reaches business logic or a data file.
 */
public final class InputValidator {

    /** 4-20 chars, starts with a letter, then letters, digits or underscore. */
    private static final Pattern USERNAME = Pattern.compile("^[a-z][a-z0-9_]{3,19}$");

    private InputValidator() {
    }

    /**
     * Validates and normalises a username to lower case, so "Ghost" and "ghost"
     * cannot exist as two different accounts (prevents look-alike impersonation).
     * The whitelist also guarantees no delimiters or newlines can reach our files
     */
    public static String username(String raw) {
        if (raw == null) {
            throw new ValidationException("Username is required");
        }
        String normalised = raw.strip().toLowerCase(Locale.ROOT);
        if (!USERNAME.matcher(normalised).matches()) {
            throw new ValidationException(
                    "Username must be 4-20 characters, start with a letter, and use only letters, digits or _");
        }
        return normalised;
    }
}