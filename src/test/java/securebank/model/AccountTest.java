package securebank.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigDecimal;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import securebank.exception.InsufficientFundsException;
import securebank.exception.ValidationException;

class AccountTest {

    private static final Instant NOW = Instant.parse("2026-10-07T08:00:00Z");
    private static final String NUMBER = "6200000005"; // valid Luhn check digit

    private static BigDecimal usd(String s) {
        return new BigDecimal(s);
    }

    @Test
    void depositAndWithdrawUpdateBalanceExactly() {
        Account a = new Account(NUMBER, "ghost1473", NOW);
        a.deposit(usd("0.10"));
        a.deposit(usd("0.20"));
        assertEquals(usd("0.30"), a.getBalance()); // would be 0.30000000000000004 with double
        a.withdraw(usd("0.30"));
        assertEquals(Money.ZERO, a.getBalance());
    }

    @Test
    void cannotOverdraw() {
        Account a = new Account(NUMBER, "ghost1473", NOW);
        a.deposit(usd("50.00"));
        assertThrows(InsufficientFundsException.class, () -> a.withdraw(usd("50.01")));
        assertEquals(usd("50.00"), a.getBalance()); // unchanged after the failed attempt
    }

    @Test
    void rejectsZeroNegativeAndOverPreciseAmounts() {
        Account a = new Account(NUMBER, "ghost1473", NOW);
        assertThrows(IllegalArgumentException.class, () -> a.deposit(usd("0")));
        assertThrows(IllegalArgumentException.class, () -> a.deposit(usd("-5.00")));
        assertThrows(IllegalArgumentException.class, () -> a.deposit(usd("1.005")));
        assertThrows(IllegalArgumentException.class, () -> a.withdraw(usd("-5.00")));
    }

    @Test
    void rejectsCorruptStoredState() {
        assertThrows(IllegalArgumentException.class,
                () -> new Account(NUMBER, "ghost1473", usd("-1.00"), NOW));
        assertThrows(ValidationException.class,
                () -> new Account("6200000006", "ghost1473", NOW)); // wrong check digit
    }

    @Test
    void transactionRejectsNegativeBalance() {
        assertThrows(IllegalArgumentException.class, () -> new Transaction("id", NUMBER,
                TransactionType.WITHDRAWAL, usd("5.00"), usd("-1.00"), NOW));
    }
}
