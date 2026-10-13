package securebank.service;

import java.math.BigDecimal;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;
import securebank.exception.AccountNotFoundException;
import securebank.exception.LimitExceededException;
import securebank.model.Account;
import securebank.model.Money;
import securebank.model.Transaction;
import securebank.model.TransactionType;
import securebank.repository.AccountRepository;
import securebank.repository.TransactionRepository;
import securebank.security.AccountNumberGenerator;
import securebank.security.AuditLogger;
import securebank.security.InputValidator;
import securebank.security.Session;

/*
 * Handles the main banking operations, including opening accounts,
 * checking balances, depositing money and making withdrawals.
 * Each operation checks the user's session and account ownership,
 * applies the necessary limit and records transactions when money
 * moves. A lock helps keep balance updates and transaction records
 * consistent
 */
public final class AccountService {

    public static final int MAX_ACCOUNTS_PER_USER = 3;
    public static final BigDecimal MAX_PER_TRANSACTION = new BigDecimal("10000.00");
    public static final BigDecimal DAILY_WITHDRAWAL_LIMIT = new BigDecimal("5000.00");
    public static final BigDecimal REAUTH_THRESHOLD = new BigDecimal("1000.00");
    public static final BigDecimal MAX_BALANCE = new BigDecimal("1000000.00");
    private static final Duration DAY = Duration.ofHours(24);
    private static final int MAX_NUMBER_ATTEMPTS = 20;

    private final AccountRepository accounts;
    private final TransactionRepository transactions;
    private final AuthService auth;
    private final AccountNumberGenerator numbers;
    private final Clock clock;
    private final AuditLogger audit;
    // Keeps money movements synchronized so balance updates and
// transaction records are handled together
    private final ReentrantLock lock = new ReentrantLock();

    // Used when audit logging is not required such as in unit tests
    public AccountService(AccountRepository accounts, TransactionRepository transactions,
                          AuthService auth, AccountNumberGenerator numbers, Clock clock) {
        this(accounts, transactions, auth, numbers, clock, AuditLogger.disabled());
    }

    public AccountService(AccountRepository accounts, TransactionRepository transactions,
                          AuthService auth, AccountNumberGenerator numbers, Clock clock,
                          AuditLogger audit) {
        this.audit = Objects.requireNonNull(audit, "audit");
        this.accounts = Objects.requireNonNull(accounts, "accounts");
        this.transactions = Objects.requireNonNull(transactions, "transactions");
        this.auth = Objects.requireNonNull(auth, "auth");
        this.numbers = Objects.requireNonNull(numbers, "numbers");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public Account openAccount(Session session) {
        Instant now = touch(session);
        lock.lock();
        try {
            if (accounts.findByOwner(session.getUsername()).size() >= MAX_ACCOUNTS_PER_USER) {
                throw new LimitExceededException(
                        "You can have at most " + MAX_ACCOUNTS_PER_USER + " accounts.");
            }
            for (int i = 0; i < MAX_NUMBER_ATTEMPTS; i++) {
                Account account = new Account(numbers.next(), session.getUsername(), now);
                if (accounts.add(account)) {
                    audit.log("ACCOUNT_OPENED", session.getUsername(), "account=" + AuditLogger.mask(account.getAccountNumber()));
                    return account;
                }
            }
            throw new IllegalStateException("Could not allocate an account number");
        } finally {
            lock.unlock();
        }
    }

    public List<Account> listAccounts(Session session) {
        touch(session);
        return accounts.findByOwner(session.getUsername());
    }

    public BigDecimal getBalance(Session session, String accountNumber) {
        touch(session);
        return requireOwned(session, accountNumber).getBalance();
    }

    public List<Transaction> history(Session session, String accountNumber) {
        touch(session);
        Account account = requireOwned(session, accountNumber);
        return transactions.findByAccount(account.getAccountNumber());
    }

    public Transaction deposit(Session session, String accountNumber, BigDecimal amount) {
        Instant now = touch(session);
        BigDecimal value = checkAmount(amount);
        lock.lock();
        try {
            Account account = requireOwned(session, accountNumber);
            if (account.getBalance().add(value).compareTo(MAX_BALANCE) > 0) {
                throw new LimitExceededException(
                        "Deposit would exceed the maximum balance of " + Money.format(MAX_BALANCE) + ".");
            }
            BigDecimal newBalance = account.deposit(value);
            audit.log("DEPOSIT", session.getUsername(),
                    "account=" + AuditLogger.mask(account.getAccountNumber()) + " amount=" + value.toPlainString());
            return record(account, TransactionType.DEPOSIT, value, newBalance, now);
        } finally {
            lock.unlock();
        }
    }

    // Checks whether the withdrawal amount requires another password check
    public boolean requiresReauthentication(BigDecimal amount) {
        return amount.compareTo(REAUTH_THRESHOLD) > 0;
    }

    /*
     * Withdraws money from an account after checking the amount and ownership
     * Withdrawals above the set threshold require password confirmation
     */
    public Transaction withdraw(Session session, String accountNumber, BigDecimal amount,
                                char[] confirmPassword) {
        Instant now = touch(session);
        BigDecimal value = checkAmount(amount);
        Account owned = requireOwned(session, accountNumber); // check ownership before asking for password
        if (requiresReauthentication(value)) {
            auth.reauthenticate(session, confirmPassword);
        }
        lock.lock();
        try {
            BigDecimal withdrawnToday = withdrawnInLast24Hours(session.getUsername(), now);
            if (withdrawnToday.add(value).compareTo(DAILY_WITHDRAWAL_LIMIT) > 0) {
                audit.log("LIMIT_EXCEEDED", session.getUsername(), "type=daily_withdrawal amount=" + value.toPlainString());
                BigDecimal left = DAILY_WITHDRAWAL_LIMIT.subtract(withdrawnToday).max(Money.ZERO);
                throw new LimitExceededException("Daily withdrawal limit is "
                        + Money.format(DAILY_WITHDRAWAL_LIMIT) + ". You can withdraw "
                        + Money.format(left) + " more in the next 24 hours.");
            }
            BigDecimal newBalance = owned.withdraw(value); // throws if insufficient funds
            audit.log("WITHDRAWAL", session.getUsername(),
                    "account=" + AuditLogger.mask(owned.getAccountNumber()) + " amount=" + value.toPlainString()
                    + (requiresReauthentication(value) ? " reauth=yes" : ""));
            return record(owned, TransactionType.WITHDRAWAL, value, newBalance, now);
        } finally {
            lock.unlock();
        }
    }

    // ---------- helpers ----------

    private Instant touch(Session session) {
        Objects.requireNonNull(session, "session");
        Instant now = clock.instant();
        session.touch(now);
        return now;
    }

    /*
     * Checks whether the account exists and belongs to the logged-in user
     * Both cases return the same error message so users cannot discover
     * other accounts by trying different account numbers
     */
    private Account requireOwned(Session session, String accountNumber) {
        String number = InputValidator.accountNumber(accountNumber);
        Account account = accounts.findByNumber(number).orElse(null);
        if (account == null || !account.isOwnedBy(session.getUsername())) {
            // The user sees one message; the audit log records which case it really was
            audit.log(account == null ? "ACCOUNT_NOT_FOUND" : "ACCESS_DENIED", session.getUsername(),
                    "account=" + AuditLogger.mask(number));
            throw new AccountNotFoundException();
        }
        return account;
    }

    private static BigDecimal checkAmount(BigDecimal amount) {
        BigDecimal value = Money.normalise(amount);
        if (!Money.isPositive(value)) {
            throw new IllegalArgumentException("Amount must be greater than zero");
        }
        if (value.compareTo(MAX_PER_TRANSACTION) > 0) {
            throw new LimitExceededException(
                    "The maximum per transaction is " + Money.format(MAX_PER_TRANSACTION) + ".");
        }
        return value;
    }

    // Adds up withdrawals from all the user's accounts over the last
    // 24 hours preventing extra accounts from increasing the daily limit
    private BigDecimal withdrawnInLast24Hours(String username, Instant now) {
        Instant since = now.minus(DAY);
        BigDecimal total = Money.ZERO;
        for (Account a : accounts.findByOwner(username)) {
            for (Transaction t : transactions.findByAccount(a.getAccountNumber())) {
                if (t.type() == TransactionType.WITHDRAWAL && t.timestamp().isAfter(since)) {
                    total = total.add(t.amount());
                }
            }
        }
        return total;
    }

    private Transaction record(Account account, TransactionType type, BigDecimal amount,
                               BigDecimal newBalance, Instant now) {
        Transaction tx = new Transaction(UUID.randomUUID().toString(), account.getAccountNumber(),
                type, amount, newBalance, now);
        accounts.update(account);
        transactions.append(tx);
        return tx;
    }
}
