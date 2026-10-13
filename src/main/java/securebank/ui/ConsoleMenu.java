package securebank.ui;

import java.io.Console;
import java.math.BigDecimal;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import securebank.exception.BankException;
import securebank.exception.SessionExpiredException;
import securebank.exception.ValidationException;
import securebank.model.Account;
import securebank.model.Money;
import securebank.model.Transaction;
import securebank.security.InputValidator;
import securebank.security.Session;
import securebank.service.AccountService;
import securebank.service.AuthService;

/*
 * Handles the text menus and user interaction in the banking application
 * This class collects input and displays results, while the service layer
 * handles the actual banking rules and security checks
 *
 * User input is passed to printf through "%s" rather than being used as the
 * format string itself. This prevents user-supplied text from being treated
 * as formatting instructions
 */
public final class ConsoleMenu {

    private static final DateTimeFormatter TIME =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(ZoneId.systemDefault());

    private final Console console;
    private final AuthService auth;
    private final AccountService bank;

    public ConsoleMenu(Console console, AuthService auth, AccountService bank) {
        this.console = Objects.requireNonNull(console, "console");
        this.auth = Objects.requireNonNull(auth, "auth");
        this.bank = Objects.requireNonNull(bank, "bank");
    }

    public void run() {
        console.printf("=== Secure Banking Application ===%n");

        while (true) {
            console.printf("%n1) Register%n2) Login%n3) Exit%n");
            String choice = console.readLine("Choose: ");

            if (choice == null) {
                return; // The input stream was closed, for example by pressing Ctrl+D
            }

            try {
                switch (choice.strip()) {
                    case "1" -> register();
                    case "2" -> login();
                    case "3" -> {
                        console.printf("Goodbye.%n");
                        return;
                    }
                    default -> console.printf("Invalid option.%n");
                }
            } catch (BankException e) {
                console.printf("%s%n", e.getMessage());
            } catch (RuntimeException e) {
                // Keep internal errors and stack traces hidden from the user
                console.printf("Something went wrong. Please try again.%n");
            }
        }
    }

    // ---------- logged out ----------

    private void register() {
        String username = console.readLine("Username: ");
        char[] password = console.readPassword("Password: ");
        char[] confirm = console.readPassword("Confirm password: ");

        try {
            if (username == null || password == null || confirm == null) {
                return;
            }

            // Make sure both password entries match before attempting registration
            if (!Arrays.equals(password, confirm)) {
                console.printf("Passwords do not match.%n");
                return;
            }

            auth.register(username, password);
            console.printf("Account created. You can now log in.%n");
        } catch (ValidationException e) {
            // Show validation problems so the user can correct their input
            console.printf("Registration failed:%n");
            for (String problem : e.getProblems()) {
                console.printf("  - %s%n", problem);
            }
        } finally {
            // Clear both password arrays from memory when registration finishes
            wipe(password);
            wipe(confirm);
        }
    }

    private void login() {
        String username = console.readLine("Username: ");
        char[] password = console.readPassword("Password: ");
        Session session;

        try {
            session = auth.login(username, password);
        } finally {
            // Clear the password whether login succeeds or fails
            wipe(password);
        }

        console.printf("Welcome, %s.%n", session.getUsername());
        bankingMenu(session);
    }

    // ---------- logged in ----------

    private void bankingMenu(Session session) {
        while (true) {
            console.printf("%n1) Open new account%n2) My accounts and balances%n3) Deposit%n"
                    + "4) Withdraw%n5) Transaction history%n6) Logout%n");

            String choice = console.readLine("Choose: ");

            if (choice == null || "6".equals(choice.strip())) {
                // Invalidate the session before returning to the logged-out menu
                session.invalidate();
                console.printf("Logged out.%n");
                return;
            }

            try {
                switch (choice.strip()) {
                    case "1" -> openAccount(session);
                    case "2" -> listAccounts(session);
                    case "3" -> deposit(session);
                    case "4" -> withdraw(session);
                    case "5" -> history(session);
                    default -> console.printf("Invalid option.%n");
                }
            } catch (SessionExpiredException e) {
                console.printf("%s%n", e.getMessage());
                return; // Return to the logged-out menu when the session expires
            } catch (BankException e) {
                console.printf("%s%n", e.getMessage());
            }
        }
    }

    private void openAccount(Session session) {
        Account account = bank.openAccount(session);
        console.printf("New account opened: %s%n", account.getAccountNumber());
    }

    private void listAccounts(Session session) {
        List<Account> mine = bank.listAccounts(session);

        if (mine.isEmpty()) {
            console.printf("You have no accounts yet. Choose 1 to open one.%n");
            return;
        }

        // Display each account number alongside its current balance
        for (Account a : mine) {
            console.printf("  %s   %s%n", a.getAccountNumber(), Money.format(a.getBalance()));
        }
    }

    private void deposit(Session session) {
        String number = chooseAccount(session);

        if (number == null) {
            return;
        }

        BigDecimal amount = InputValidator.amount(console.readLine("Amount to deposit: "));
        Transaction tx = bank.deposit(session, number, amount);

        console.printf("Deposited %s. New balance: %s%n",
                Money.format(tx.amount()), Money.format(tx.balanceAfter()));
    }

    private void withdraw(Session session) {
        String number = chooseAccount(session);

        if (number == null) {
            return;
        }

        BigDecimal amount = InputValidator.amount(console.readLine("Amount to withdraw: "));
        char[] password = null;

        try {
            // Larger withdrawals require the user to confirm their identity again
            if (bank.requiresReauthentication(amount)) {
                console.printf("Withdrawals over %s need your password.%n",
                        Money.format(AccountService.REAUTH_THRESHOLD));
                password = console.readPassword("Password: ");
            }

            Transaction tx = bank.withdraw(session, number, amount, password);

            console.printf("Withdrew %s. New balance: %s%n",
                    Money.format(tx.amount()), Money.format(tx.balanceAfter()));
        } finally {
            // Clear the reauthentication password after the withdrawal attempt
            wipe(password);
        }
    }

    private void history(Session session) {
        String number = chooseAccount(session);

        if (number == null) {
            return;
        }

        List<Transaction> txs = bank.history(session, number);

        if (txs.isEmpty()) {
            console.printf("No transactions yet.%n");
            return;
        }

        console.printf("  %-16s  %-10s  %16s  %16s%n", "Date", "Type", "Amount", "Balance");

        // Show the date, transaction type, amount and resulting balance
        for (Transaction t : txs) {
            console.printf("  %-16s  %-10s  %16s  %16s%n", TIME.format(t.timestamp()), t.type(),
                    Money.format(t.amount()), Money.format(t.balanceAfter()));
        }
    }

    /*
     * Lets the user select one of their own accounts
     * If there is only one account, it is selected automatically
     * Any manually entered account number is still checked for ownership
     * by the service layer before a banking operation is performed
     */
    private String chooseAccount(Session session) {
        List<Account> mine = bank.listAccounts(session);

        if (mine.isEmpty()) {
            console.printf("You have no accounts yet. Choose 1 to open one.%n");
            return null;
        }

        if (mine.size() == 1) {
            return mine.get(0).getAccountNumber();
        }

        // Number the available accounts to make selection easier
        for (int i = 0; i < mine.size(); i++) {
            console.printf("  %d) %s%n", i + 1, mine.get(i).getAccountNumber());
        }

        String pick = console.readLine("Account: ");

        if (pick == null) {
            return null;
        }

        pick = pick.strip();

        // Convert a menu number into the corresponding account number
        for (int i = 0; i < mine.size(); i++) {
            if (pick.equals(String.valueOf(i + 1))) {
                return mine.get(i).getAccountNumber();
            }
        }

        // Allow an account number to be entered directly; the service checks ownership
        return pick;
    }

    // Overwrites a password array so its contents are not left in memory unnecessarily
    private static void wipe(char[] secret) {
        if (secret != null) {
            Arrays.fill(secret, '\0');
        }
    }
}