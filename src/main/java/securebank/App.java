package securebank;

import java.io.Console;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import securebank.exception.BankException;
import securebank.exception.DataIntegrityException;
import securebank.security.AccountNumberGenerator;
import securebank.security.AuditLogger;
import securebank.security.IntegrityService;
import securebank.security.LoginThrottler;
import securebank.security.PasswordHasher;
import securebank.security.PasswordPolicy;
import securebank.service.AccountService;
import securebank.service.AuthService;
import securebank.storage.DataDirectory;
import securebank.storage.FileAccountRepository;
import securebank.storage.FileTransactionRepository;
import securebank.storage.FileUserRepository;
import securebank.storage.LedgerVerifier;
import securebank.storage.SignedDataFile;
import securebank.ui.ConsoleMenu;

/*
 * Starts the banking application by opening and verifying its data files
 * Then creates the required services and connects them before displaying the console menu
 */
public final class App {

    private static final Path DATA_DIR = Path.of("data");
    private static final String USERS = "users.txt";
    private static final String ACCOUNTS = "accounts.txt";
    private static final String TRANSACTIONS = "transactions.txt";
    private static final Path AUDIT_LOG = Path.of("logs", "audit.log");

    private App() {
        // Prevents this class from being instantiated
    }

    public static void main(String[] args) {
        Console console = System.console();

        if (console == null) {
            // A real terminal is required so passwords are not displayed while being entered
            System.err.println("No secure console detected. Run from a terminal: java -jar target/securebank.jar");
            System.exit(1);
        }

        Clock clock = Clock.systemUTC();
        AuditLogger audit = AuditLogger.toFile(AUDIT_LOG, clock);

        try (DataDirectory data = DataDirectory.open(DATA_DIR)) {
            Path keyFile = data.file(".secret.key");

            // Check with the user before creating a new key so cancelling does not change existing data
            boolean needsTrust = !Files.exists(keyFile) && anyExist(data, USERS, ACCOUNTS, TRANSACTIONS);

            if (needsTrust && !confirmTrust(console)) {
                audit.log("STARTUP_CANCELLED", "-", "reason=unsigned_data_not_trusted");
                console.printf("Start-up cancelled. No data was changed.%n");
                return;
            }

            IntegrityService integrity = IntegrityService.loadOrCreate(keyFile);

            if (needsTrust) {
                // Allow existing files to be accepted and signed with the newly created integrity key
                integrity.trustUnsignedFiles();
                audit.log("DATA_TRUSTED", "-", "reason=new_integrity_key files=re-signed");
            }

            // Load user records and verify their file integrity
            FileUserRepository users = new FileUserRepository(
                    new SignedDataFile(data.file(USERS), FileUserRepository.HEADER, integrity));

            // Load account records and verify their file integrity
            FileAccountRepository accounts = new FileAccountRepository(
                    new SignedDataFile(data.file(ACCOUNTS), FileAccountRepository.HEADER, integrity));

            // Load transaction records and verify their hash chain
            FileTransactionRepository transactions = new FileTransactionRepository(
                    new SignedDataFile(data.file(TRANSACTIONS), FileTransactionRepository.HEADER, integrity));

            // Confirm that each account balance matches its transaction history
            LedgerVerifier.verify(accounts, transactions);

            // Set up authentication and account services with their required dependencies
            AuthService auth = new AuthService(users, new PasswordHasher(), new PasswordPolicy(),
                    new LoginThrottler(), clock, audit);

            AccountService bank = new AccountService(accounts, transactions, auth,
                    new AccountNumberGenerator(), clock, audit);

            audit.log("APP_STARTED", "-", "integrity=verified");

            // Hand control over to the console menu
            new ConsoleMenu(console, auth, bank).run();

        } catch (DataIntegrityException e) {
            // Stop the application if stored data fails an integrity check
            audit.log("INTEGRITY_ALERT", "-", e.getMessage());
            System.err.println("SECURITY ALERT: " + e.getMessage());
            System.err.println("The application will not run on data it cannot trust.");
            System.exit(2);
        } catch (BankException e) {
            System.err.println(e.getMessage());
            System.exit(1);
        } catch (IOException e) {
            System.err.println("Could not open the data folder.");
            System.exit(1);
        }
    }

    private static boolean anyExist(DataDirectory data, String... names) {
        for (String name : names) {
            if (Files.exists(data.file(name))) {
                return true;
            }
        }

        return false;
    }

    /*
     * Handles the situation where data files already exist but the integrity key is missing
     * The user must decide whether to trust these files before the application signs them again
     */
    private static boolean confirmTrust(Console console) {
        console.printf("%nWARNING: No integrity key was found, but data files exist.%n"
                + "This is expected the first time you run a fresh copy of the project.%n"
                + "If you did NOT just download or clone it, the key may have been deleted%n"
                + "to hide tampering. The hash chain and balance checks will still run.%n");

        String answer = console.readLine("Type TRUST to accept and re-sign the existing files: ");

        return answer != null && "TRUST".equals(answer.strip());
    }
}