package securebank.model;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Objects;
import securebank.exception.InsufficientFundsException;
import securebank.security.InputValidator;

/*
 * Represents a bank account
 * The balance is private and has no setter, it can only be changed through deposit and withdraw
 * These methods make sure the balance never goes below zero and always has 2 decimal places
 *
 * Balance operations are synchronized so two threads cant change the balance at the same time
 * and accidentally overwrite each other's updates
 */
public final class Account {

    private final String accountNumber;
    private final String ownerUsername;
    private final Instant createdAt;
    private BigDecimal balance;

    /** Opens a new account with a zero balance */
    public Account(String accountNumber, String ownerUsername, Instant createdAt) {
        this(accountNumber, ownerUsername, Money.ZERO, createdAt);
    }

    /** Loads an account from storage and checks that its data is valid */
    public Account(String accountNumber, String ownerUsername, BigDecimal balance, Instant createdAt) {
        this.accountNumber = InputValidator.accountNumber(accountNumber);
        this.ownerUsername = InputValidator.username(ownerUsername);
        this.createdAt = Objects.requireNonNull(createdAt, "createdAt");

        BigDecimal b = Money.normalise(balance);
        if (b.signum() < 0) {
            throw new IllegalArgumentException("Balance cannot be negative");
        }

        this.balance = b;
    }

    public String getAccountNumber() {
        return accountNumber;
    }

    public String getOwnerUsername() {
        return ownerUsername;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public boolean isOwnedBy(String username) {
        return ownerUsername.equals(username);
    }

    public synchronized BigDecimal getBalance() {
        return balance; // BigDecimal is immutable, so its safe to return it directly
    }

    /** Adds money to the account and returns the updated balance */
    public synchronized BigDecimal deposit(BigDecimal amount) {
        BigDecimal a = requirePositive(amount);
        balance = balance.add(a);
        return balance;
    }

    /** Takes money out of the account and throws an error if there isnt enough */
    public synchronized BigDecimal withdraw(BigDecimal amount) {
        BigDecimal a = requirePositive(amount);
        if (balance.compareTo(a) < 0) {
            throw new InsufficientFundsException();
        }

        balance = balance.subtract(a);
        return balance;
    }

    private static BigDecimal requirePositive(BigDecimal amount) {
        BigDecimal a = Money.normalise(amount);
        if (!Money.isPositive(a)) {
            throw new IllegalArgumentException("Amount must be greater than zero");
        }
        return a;
    }

    @Override
    public String toString() {
        return "Account[" + accountNumber + "]"; // Keep the balance out of logs
    }
}