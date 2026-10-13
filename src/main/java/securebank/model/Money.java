package securebank.model;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Locale;

/*
 * Keeps all money rules in one place
 * We use BigDecimal with exactly 2 decimal places instead of double
 * Double can cause small calculation errors, which isnt acceptable when handling money
 */
public final class Money {

    public static final int SCALE = 2;
    public static final BigDecimal ZERO = BigDecimal.ZERO.setScale(SCALE);

    private Money() {
    }

    /*
     * Makes sure an amount has exactly 2 decimal places
     * If rounding would be needed, it throws an error instead of silently changing the amount
     * For example, 10.005 cant be stored as money with 2 decimal places without rounding
     */
    public static BigDecimal normalise(BigDecimal amount) {
        if (amount == null) {
            throw new IllegalArgumentException("Amount is required");
        }

        try {
            return amount.setScale(SCALE, RoundingMode.UNNECESSARY);
        } catch (ArithmeticException e) {
            throw new IllegalArgumentException("Amount has more than 2 decimal places", e);
        }
    }

    public static boolean isPositive(BigDecimal amount) {
        return amount.compareTo(BigDecimal.ZERO) > 0;
    }

    /** Formats an amount for display, for example USD 1,250.00 */
    public static String format(BigDecimal amount) {
        return String.format(Locale.ROOT, "USD %,.2f", amount); // Keeps the output the same on every machine
    }
}