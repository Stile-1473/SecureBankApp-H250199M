package securebank.security;

import java.security.SecureRandom;

/*
 * Generates 10-digit account numbers using the bank prefix 62, seven random digits
 * and a final Luhn check digit to help catch typing mistakes
 * SecureRandom makes the random part harder to predict or guess
 */
public final class AccountNumberGenerator {

    private static final String PREFIX = "62";
    private static final int RANDOM_DIGITS = 7;

    private final SecureRandom random = new SecureRandom();

    public String next() {
        StringBuilder sb = new StringBuilder(PREFIX);
        for (int i = 0; i < RANDOM_DIGITS; i++) {
            sb.append(random.nextInt(10));
        }
        sb.append(luhnCheckDigit(sb.toString()));
        return sb.toString();
    }

    /** Checks whether the last digit matches the Luhn check digit */
    public static boolean isLuhnValid(String digits) {
        if (digits == null || digits.length() < 2) {
            return false;
        }

        String body = digits.substring(0, digits.length() - 1);
        int check = digits.charAt(digits.length() - 1) - '0';

        return luhnCheckDigit(body) == check;
    }

    /*
     * Works out the Luhn check digit by doubling every second digit from the right
     * If a doubled digit is above 9, subtract 9, then add all the digits together
     * The final digit makes the total a multiple of 10
     */
    static int luhnCheckDigit(String body) {
        int sum = 0;
        boolean doubleIt = true;

        for (int i = body.length() - 1; i >= 0; i--) {
            int d = body.charAt(i) - '0';

            if (d < 0 || d > 9) {
                throw new IllegalArgumentException("Digits only");
            }

            if (doubleIt) {
                d *= 2;
                if (d > 9) {
                    d -= 9;
                }
            }

            sum += d;
            doubleIt = !doubleIt;
        }

        return (10 - (sum % 10)) % 10;
    }
}