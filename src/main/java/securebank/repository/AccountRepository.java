package securebank.repository;

import java.util.List;
import java.util.Optional;
import securebank.model.Account;

/*
 * Handles storing and retrieving accounts
 * The rest of the app uses this interface instead of depending on how accounts are stored
 */
public interface AccountRepository {

    Optional<Account> findByNumber(String accountNumber);

    List<Account> findByOwner(String username);

    /* Returns every account, used when checking data integrity at startup */
    List<Account> findAll();

    /* Adds a new account and returns false if the account number is already taken */
    boolean add(Account account);

    /* Saves changes to an existing account */
    void update(Account account);
}