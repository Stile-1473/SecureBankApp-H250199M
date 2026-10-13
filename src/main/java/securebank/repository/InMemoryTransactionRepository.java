package securebank.repository;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import securebank.model.Transaction;

public final class InMemoryTransactionRepository implements TransactionRepository {

    private final List<Transaction> transactions = new ArrayList<>();

    @Override
    public synchronized void append(Transaction transaction) {
        transactions.add(Objects.requireNonNull(transaction, "transaction"));
    }

    @Override
    public synchronized List<Transaction> findByAccount(String accountNumber) {
        return transactions.stream()
                .filter(t -> t.accountNumber().equals(accountNumber))
                .toList();
    }
}
