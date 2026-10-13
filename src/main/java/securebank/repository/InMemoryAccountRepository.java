package securebank.repository;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import securebank.model.Account;

public final class InMemoryAccountRepository implements AccountRepository {

    private final Map<String, Account> accounts = new ConcurrentHashMap<>();

    @Override
    public Optional<Account> findByNumber(String accountNumber) {
        if (accountNumber == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(accounts.get(accountNumber));
    }

    @Override
    public List<Account> findByOwner(String username) {
        return accounts.values().stream()
                .filter(a -> a.isOwnedBy(username))
                .sorted(Comparator.comparing(Account::getCreatedAt))
                .toList(); // unmodifiable
    }

    @Override
    public List<Account> findAll() {
        return List.copyOf(accounts.values());
    }

    @Override
    public boolean add(Account account) {
        Objects.requireNonNull(account, "account");
        return accounts.putIfAbsent(account.getAccountNumber(), account) == null;
    }

    @Override
    public void update(Account account) {
        Objects.requireNonNull(account, "account");
        if (accounts.replace(account.getAccountNumber(), account) == null) {
            throw new IllegalStateException("Cannot update an account that does not exist");
        }
    }
}
