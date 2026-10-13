package securebank.model;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Objects;

/*
 * Represents one entry in an account's transaction history
 * Once a transaction is created, its details cant be changed
 * If something needs correcting, another transaction must be added instead
 */
public record Transaction(
        String id,
        String accountNumber,
        TransactionType type,
        BigDecimal amount,
        BigDecimal balanceAfter,
        Instant timestamp) {

    /* Checks all fields when creating a transaction, including records loaded from a file */
    public Transaction {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(accountNumber, "accountNumber");
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(timestamp, "timestamp");

        amount = Money.normalise(amount);
        balanceAfter = Money.normalise(balanceAfter);

        if (!Money.isPositive(amount)) {
            throw new IllegalArgumentException("Transaction amount must be positive");
        }

        if (balanceAfter.signum() < 0) {
            throw new IllegalArgumentException("Balance can never be negative");
        }
    }
}