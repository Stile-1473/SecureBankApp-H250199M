package securebank.storage;

import java.math.BigDecimal;
import java.util.List;
import securebank.exception.DataIntegrityException;
import securebank.model.Account;
import securebank.model.Money;
import securebank.model.Transaction;
import securebank.model.TransactionType;
import securebank.repository.AccountRepository;
import securebank.repository.TransactionRepository;
import securebank.security.AuditLogger;

/*
 * Checks account balances against their transaction histories when the
 * application starts. It replays each account's transactions from zero and
 * verifies that the final balance matches the balance saved for the account
 *
 * This helps detect problems that file signatures and hash chains might not
 * catch on their own, such as a crash between saving a transaction and updating
 * an account balance or a balance being changed by someone with access to the
 * signing key
 */
public final class LedgerVerifier {

    private LedgerVerifier() {
    }

    public static void verify(AccountRepository accounts, TransactionRepository transactions) {
        for (Account account : accounts.findAll()) {
            BigDecimal running = Money.ZERO;
            List<Transaction> history = transactions.findByAccount(account.getAccountNumber());

            for (Transaction t : history) {
                // Deposits increase the balance, while withdrawals reduce it
                running = t.type() == TransactionType.DEPOSIT
                        ? running.add(t.amount())
                        : running.subtract(t.amount());

                // Each transaction must produce its recorded balance and must
                // never leave the account with a negative balance
                if (running.signum() < 0 || running.compareTo(t.balanceAfter()) != 0) {
                    throw new DataIntegrityException("Transaction history for account "
                            + mask(account.getAccountNumber()) + " does not add up.");
                }
            }

            // The balance calculated from all transactions must match the
            // balance currently stored for the account
            if (running.compareTo(account.getBalance()) != 0) {
                throw new DataIntegrityException("Balance of account "
                        + mask(account.getAccountNumber())
                        + " does not match its transaction history.");
            }
        }
    }

    // Hides all but the last four digits of an account number, for example,
    // ******1234, so error messages do not expose the full account number
    static String mask(String accountNumber) {
        return AuditLogger.mask(accountNumber);
    }
}