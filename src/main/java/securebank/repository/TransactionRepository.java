package securebank.repository;

import java.util.List;
import securebank.model.Transaction;

/*
 * Stores the transaction history, records can only be added, not edited or deleted
 * If a financial record needs correcting, we add another transaction instead of changing the old one
 * This keeps the history intact for auditing
 */
public interface TransactionRepository {

    void append(Transaction transaction);

    /* Returns all transactions for an account, starting with the oldest */
    List<Transaction> findByAccount(String accountNumber);
}