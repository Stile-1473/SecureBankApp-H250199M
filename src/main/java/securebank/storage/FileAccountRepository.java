package securebank.storage;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import securebank.exception.DataIntegrityException;
import securebank.exception.StorageException;
import securebank.model.Account;
import securebank.repository.AccountRepository;

/*
 * Loads accounts from accounts.txt and saves any changes made to them.
 * Each record contains the account number, owner's username, balance,
 * and account creation time
 */
public final class FileAccountRepository implements AccountRepository {

    public static final String HEADER = "# securebank accounts v1";

    private final SignedDataFile file;
    private final Map<String, Account> accounts = new LinkedHashMap<>();

    public FileAccountRepository(SignedDataFile file) {
        this.file = Objects.requireNonNull(file, "file");
        List<String> lines = file.readLines();
        for (int i = 0; i < lines.size(); i++) {
            Account a = parse(lines.get(i), new RecordCodec(file.name(), i + 2));
            if (accounts.putIfAbsent(a.getAccountNumber(), a) != null) {
                throw new DataIntegrityException(file.name() + ": duplicate account number.");
            }
        }
        if (file.acceptedUnsigned()) {
            save();
        }
    }

    @Override
    public synchronized Optional<Account> findByNumber(String accountNumber) {
        return Optional.ofNullable(accountNumber == null ? null : accounts.get(accountNumber));
    }

    @Override
    public synchronized List<Account> findByOwner(String username) {
        return accounts.values().stream()
                .filter(a -> a.isOwnedBy(username))
                .sorted(Comparator.comparing(Account::getCreatedAt))
                .toList();
    }

    @Override
    public synchronized List<Account> findAll() {
        return List.copyOf(accounts.values());
    }

    @Override
    public synchronized boolean add(Account account) {
        Objects.requireNonNull(account, "account");
        if (accounts.putIfAbsent(account.getAccountNumber(), account) != null) {
            return false;
        }
        try {
            save();
        } catch (StorageException e) {
            accounts.remove(account.getAccountNumber());
            throw e;
        }
        return true;
    }

    @Override
    public synchronized void update(Account account) {
        Objects.requireNonNull(account, "account");
        if (!accounts.containsKey(account.getAccountNumber())) {
            throw new IllegalStateException("Cannot update an account that does not exist");
        }
        accounts.put(account.getAccountNumber(), account);
        save();
    }

    private void save() {
        List<String> lines = new ArrayList<>();
        for (Account a : accounts.values()) {
            lines.add(String.join(RecordCodec.SEP,
                    a.getAccountNumber(),
                    a.getOwnerUsername(),
                    a.getBalance().toPlainString(),
                    a.getCreatedAt().toString()));
        }
        try {
            file.writeLines(lines);
        } catch (IOException e) {
            throw new StorageException(e);
        }
    }

    private static Account parse(String line, RecordCodec c) {
        String[] f = c.split(line, 4);
        try {
            return new Account(f[0], f[1], c.parseMoney(f[2]), c.parseInstant(f[3]));
        } catch (DataIntegrityException e) {
            throw e;
        } catch (RuntimeException e) {
            throw c.bad("invalid account record", e);
        }
    }
}
