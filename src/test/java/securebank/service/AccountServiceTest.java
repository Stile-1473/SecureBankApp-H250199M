package securebank.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigDecimal;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import securebank.MutableClock;
import securebank.exception.AccountNotFoundException;
import securebank.exception.AuthenticationException;
import securebank.exception.InsufficientFundsException;
import securebank.exception.LimitExceededException;
import securebank.exception.SessionExpiredException;
import securebank.model.Account;
import securebank.model.Transaction;
import securebank.model.TransactionType;
import securebank.repository.InMemoryAccountRepository;
import securebank.repository.InMemoryTransactionRepository;
import securebank.repository.InMemoryUserRepository;
import securebank.security.AccountNumberGenerator;
import securebank.security.LoginThrottler;
import securebank.security.PasswordPolicy;
import securebank.security.Session;
import securebank.security.TestHashers;

class AccountServiceTest {

    private static final String PW = "Kariba#Sunset47";

    private final MutableClock clock = new MutableClock(Instant.parse("2026-10-07T08:00:00Z"));
    private final AuthService auth = new AuthService(new InMemoryUserRepository(), TestHashers.fast(),
            new PasswordPolicy(), new LoginThrottler(), clock);
    private final InMemoryTransactionRepository txs = new InMemoryTransactionRepository();
    private final AccountService bank = new AccountService(new InMemoryAccountRepository(), txs,
            auth, new AccountNumberGenerator(), clock);

    private Session loginAs(String username) {
        auth.register(username, PW.toCharArray());
        return auth.login(username, PW.toCharArray());
    }

    private static BigDecimal usd(String s) {
        return new BigDecimal(s);
    }

    @Test
    void depositWithdrawAndHistory() {
        Session s = loginAs("ghost1473");
        String acc = bank.openAccount(s).getAccountNumber();
        bank.deposit(s, acc, usd("500.00"));
        bank.withdraw(s, acc, usd("120.50"), null);
        assertEquals(usd("379.50"), bank.getBalance(s, acc));

        var history = bank.history(s, acc);
        assertEquals(2, history.size());
        assertEquals(TransactionType.DEPOSIT, history.get(0).type());
        assertEquals(usd("379.50"), history.get(1).balanceAfter());
    }

    @Test
    void cannotTouchSomeoneElsesAccount() {
        Session ghost = loginAs("ghost1473");
        Session alice = loginAs("alice01");
        String ghostAcc = bank.openAccount(ghost).getAccountNumber();
        bank.deposit(ghost, ghostAcc, usd("100.00"));

        assertThrows(AccountNotFoundException.class, () -> bank.getBalance(alice, ghostAcc));
        assertThrows(AccountNotFoundException.class, () -> bank.deposit(alice, ghostAcc, usd("1.00")));
        assertThrows(AccountNotFoundException.class, () -> bank.withdraw(alice, ghostAcc, usd("1.00"), null));
        assertThrows(AccountNotFoundException.class, () -> bank.history(alice, ghostAcc));
        assertEquals(usd("100.00"), bank.getBalance(ghost, ghostAcc));
    }

    @Test
    void someoneElsesAccountLooksExactlyLikeAMissingOne() {
        Session ghost = loginAs("ghost1473");
        Session alice = loginAs("alice01");
        String ghostAcc = bank.openAccount(ghost).getAccountNumber();
        String others = assertThrows(AccountNotFoundException.class,
                () -> bank.getBalance(alice, ghostAcc)).getMessage();
        String missing = assertThrows(AccountNotFoundException.class,
                () -> bank.getBalance(alice, "6200000005")).getMessage();
        assertEquals(others, missing);
    }

    @Test
    void failedWithdrawalChangesNothing() {
        Session s = loginAs("ghost1473");
        String acc = bank.openAccount(s).getAccountNumber();
        bank.deposit(s, acc, usd("50.00"));
        assertThrows(InsufficientFundsException.class, () -> bank.withdraw(s, acc, usd("60.00"), null));
        assertEquals(usd("50.00"), bank.getBalance(s, acc));
        assertEquals(1, bank.history(s, acc).size());
    }

    @Test
    void perTransactionLimit() {
        Session s = loginAs("ghost1473");
        String acc = bank.openAccount(s).getAccountNumber();
        assertThrows(LimitExceededException.class, () -> bank.deposit(s, acc, usd("10000.01")));
    }

    @Test
    void largeWithdrawalNeedsCorrectPassword() {
        Session s = loginAs("ghost1473");
        String acc = bank.openAccount(s).getAccountNumber();
        bank.deposit(s, acc, usd("3000.00"));

        assertThrows(AuthenticationException.class, () -> bank.withdraw(s, acc, usd("1500.00"), null));
        assertThrows(AuthenticationException.class,
                () -> bank.withdraw(s, acc, usd("1500.00"), "Wrong#Pass9999".toCharArray()));
        assertEquals(usd("3000.00"), bank.getBalance(s, acc));

        Transaction tx = bank.withdraw(s, acc, usd("1500.00"), PW.toCharArray());
        assertEquals(usd("1500.00"), tx.balanceAfter());
    }

    @Test
    void wrongConfirmationPasswordsEndTheSession() {
        Session s = loginAs("ghost1473");
        String acc = bank.openAccount(s).getAccountNumber();
        bank.deposit(s, acc, usd("3000.00"));
        for (int i = 0; i < LoginThrottler.MAX_ATTEMPTS; i++) {
            assertThrows(AuthenticationException.class,
                    () -> bank.withdraw(s, acc, usd("1500.00"), "Wrong#Pass9999".toCharArray()));
        }
        assertFalse(s.isValidAt(clock.instant()));
    }

    @Test
    void dailyLimitCoversAllAccountsAndResetsAfter24Hours() {
        Session s = loginAs("ghost1473");
        String a1 = bank.openAccount(s).getAccountNumber();
        String a2 = bank.openAccount(s).getAccountNumber();
        bank.deposit(s, a1, usd("9000.00"));
        bank.deposit(s, a2, usd("9000.00"));

        char[] pw = PW.toCharArray();
        bank.withdraw(s, a1, usd("3000.00"), pw);
        // 3000 + 2500 > 5000, even though it's a different account
        assertThrows(LimitExceededException.class, () -> bank.withdraw(s, a2, usd("2500.00"), PW.toCharArray()));
        bank.withdraw(s, a2, usd("2000.00"), PW.toCharArray()); // exactly 5000: allowed

        clock.advance(Duration.ofHours(25));
        Session later = auth.login("ghost1473", PW.toCharArray());
        bank.withdraw(later, a1, usd("1000.00"), null);
        assertEquals(usd("5000.00"), bank.getBalance(later, a1));
    }

    @Test
    void accountLimitPerUser() {
        Session s = loginAs("ghost1473");
        for (int i = 0; i < AccountService.MAX_ACCOUNTS_PER_USER; i++) {
            bank.openAccount(s);
        }
        assertThrows(LimitExceededException.class, () -> bank.openAccount(s));
    }

    @Test
    void expiredSessionIsRefused() {
        Session s = loginAs("ghost1473");
        Account acc = bank.openAccount(s);
        clock.advance(Duration.ofMinutes(6));
        assertThrows(SessionExpiredException.class,
                () -> bank.deposit(s, acc.getAccountNumber(), usd("10.00")));
    }

    @Test
    void listShowsOnlyMyAccounts() {
        Session ghost = loginAs("ghost1473");
        Session alice = loginAs("alice01");
        bank.openAccount(ghost);
        bank.openAccount(alice);
        bank.openAccount(alice);
        assertEquals(1, bank.listAccounts(ghost).size());
        assertTrue(bank.listAccounts(alice).stream().allMatch(a -> a.isOwnedBy("alice01")));
    }
}
