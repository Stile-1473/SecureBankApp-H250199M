package securebank.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigDecimal;
import org.junit.jupiter.api.Test;
import securebank.exception.ValidationException;

class AmountAndAccountNumberTest {

    @Test
    void validAmountsAreNormalisedToTwoDecimals() {
        assertEquals(new BigDecimal("150.00"), InputValidator.amount("150"));
        assertEquals(new BigDecimal("150.50"), InputValidator.amount(" 150.5 "));
        assertEquals(new BigDecimal("0.01"), InputValidator.amount("0.01"));
    }

    @Test
    void dangerousOrMalformedAmountsAreRejected() {
        String[] bad = {null, "", "-50", "+50", "1e9", "1E3", "50.123", "0", "0.00",
                        "abc", "50,00", "1 000", "NaN", "Infinity", "9999999999", ".5", "5."};
        for (String s : bad) {
            assertThrows(ValidationException.class, () -> InputValidator.amount(s));
        }
    }

    @Test
    void generatedNumbersAreValid() {
        AccountNumberGenerator gen = new AccountNumberGenerator();
        for (int i = 0; i < 1_000; i++) {
            String n = gen.next();
            assertEquals(10, n.length());
            assertTrue(n.startsWith("62"));
            assertEquals(n, InputValidator.accountNumber(n));
        }
    }

    @Test
    void luhnCatchesSingleDigitTypos() {
        String n = new AccountNumberGenerator().next();
        for (int pos = 0; pos < n.length(); pos++) {
            char original = n.charAt(pos);
            char changed = original == '9' ? '0' : (char) (original + 1);
            String typo = n.substring(0, pos) + changed + n.substring(pos + 1);
            assertFalse(AccountNumberGenerator.isLuhnValid(typo));
        }
    }

    @Test
    void malformedAccountNumbersAreRejected() {
        String[] bad = {null, "", "123", "62000000061", "62000000a6", "6200000007", "../6200000"};
        for (String s : bad) {
            assertThrows(ValidationException.class, () -> InputValidator.accountNumber(s));
        }
    }
}
