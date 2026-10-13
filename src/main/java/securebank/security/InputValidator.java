package securebank.security;

import java.math.BigDecimal;
import java.util.Locale;
import java.util.regex.Pattern;
import securebank.exception.ValidationException;
import securebank.model.Money;

/*
 * Central place for checking user input, every value must pass through here
 * before it reaches the business logic or gets saved to a data file
 */
public final class InputValidator {

    /* Username must be 4-20 chars, start with a letter and use only letters, digits or underscore */
    private static final Pattern USERNAME = Pattern.compile("^[a-z][a-z0-9_]{3,19}$");

    /* Allows digits with up to 2 decimal places and 9 digits before the point, no signs or exponents */
    private static final Pattern AMOUNT = Pattern.compile("^\\d{1,9}(\\.\\d{1,2})?$");

    /* Account numbers must contain exactly 10 digits */
    private static final Pattern ACCOUNT_NUMBER = Pattern.compile("^\\d{10}$");

    private InputValidator() {
    }

    /*
     * Checks the username and converts it to lower case, so Ghost and ghost cant become two seperate accounts
     * The allowed characters also stop delimiters or newlines from getting into our files
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

    /*
     * Checks a money amount before converting it to BigDecimal
     * This blocks inputs like -50, 1e9 or +5 which BigDecimal would otherwise accept
     */
    public static BigDecimal amount(String raw) {
        if (raw == null) {
            throw new ValidationException("Amount is required");
        }

        String s = raw.strip();

        if (!AMOUNT.matcher(s).matches()) {
            throw new ValidationException("Enter an amount like 150 or 150.75 (no signs or letters)");
        }

        BigDecimal value = Money.normalise(new BigDecimal(s));

        if (!Money.isPositive(value)) {
            throw new ValidationException("Amount must be greater than zero");
        }

        return value;
    }

    /* Checks the account number format and its Luhn check digit, which helps catch typing mistakes */
    public static String accountNumber(String raw) {
        if (raw == null) {
            throw new ValidationException("Account number is required");
        }

        String s = raw.strip();

        if (!ACCOUNT_NUMBER.matcher(s).matches() || !AccountNumberGenerator.isLuhnValid(s)) {
            throw new ValidationException("That is not a valid account number");
        }

        return s;
    }
}