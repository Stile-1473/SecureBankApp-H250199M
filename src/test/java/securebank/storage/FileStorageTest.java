package securebank.storage;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import securebank.exception.BankException;
import securebank.exception.DataIntegrityException;
import securebank.model.Account;
import securebank.model.Transaction;
import securebank.model.TransactionType;
import securebank.model.User;
import securebank.security.IntegrityService;
import securebank.security.TestHashers;

class FileStorageTest {

    private static final Instant NOW = Instant.parse("2026-10-08T08:00:00Z");
    private static final String ACC = "6200000005";

    private final Path dir;
    private final IntegrityService integrity = IntegrityService.withKey(new byte[32]);

    FileStorageTest() throws IOException {
        dir = Files.createTempDirectory("securebank-test");
    }

    // ---------- helpers ----------

    private SignedDataFile file(String name, String header, IntegrityService key) {
        return new SignedDataFile(dir.resolve(name), header, key);
    }

    private FileUserRepository users(IntegrityService key) {
        return new FileUserRepository(file("users.txt", FileUserRepository.HEADER, key));
    }

    private FileAccountRepository accounts() {
        return new FileAccountRepository(file("accounts.txt", FileAccountRepository.HEADER, integrity));
    }

    private FileTransactionRepository transactions() {
        return new FileTransactionRepository(file("transactions.txt", FileTransactionRepository.HEADER, integrity));
    }

    private static Transaction tx(String id, TransactionType type, String amount, String after) {
        return new Transaction(id, ACC, type, new BigDecimal(amount), new BigDecimal(after), NOW);
    }

    /** Builds an account with 3 transactions: +100, -30, +5 = 75. */
    private void seedLedger() {
        FileAccountRepository accounts = accounts();
        Account a = new Account(ACC, "ghost1473", NOW);
        accounts.add(a);
        FileTransactionRepository txs = transactions();
        a.deposit(new BigDecimal("100.00"));
        txs.append(tx("t1", TransactionType.DEPOSIT, "100.00", "100.00"));
        a.withdraw(new BigDecimal("30.00"));
        txs.append(tx("t2", TransactionType.WITHDRAWAL, "30.00", "70.00"));
        a.deposit(new BigDecimal("5.00"));
        txs.append(tx("t3", TransactionType.DEPOSIT, "5.00", "75.00"));
        accounts.update(a);
    }

    private List<String> recordLines(String name) throws IOException {
        List<String> lines = Files.readAllLines(dir.resolve(name), StandardCharsets.UTF_8);
        return new ArrayList<>(lines.subList(1, lines.size() - 1)); // drop header and #hmac
    }

    /** Simulates an attacker who also stole the key: writes edited records with a VALID HMAC. */
    private void rewriteSigned(String name, String header, List<String> records) throws IOException {
        file(name, header, integrity).writeLines(records);
    }

    private void editRaw(String name, String from, String to) throws IOException {
        Path p = dir.resolve(name);
        String s = Files.readString(p, StandardCharsets.UTF_8);
        assertTrue(s.contains(from), "test setup: text to edit not found");
        Files.writeString(p, s.replace(from, to), StandardCharsets.UTF_8);
    }

    // ---------- round trips ----------

    @Test
    void usersSurviveRestartIncludingLockState() {
        FileUserRepository repo = users(integrity);
        User u = new User("ghost1473", TestHashers.fast().hash("Kariba#Sunset47".toCharArray()), NOW);
        u.recordFailedLogin();
        u.lockUntil(NOW.plusSeconds(60));
        repo.add(u);

        User loaded = users(integrity).findByUsername("ghost1473").orElseThrow();
        assertEquals(1, loaded.getFailedAttempts());
        assertTrue(loaded.isLockedAt(NOW));
        assertTrue(TestHashers.fast().verify("Kariba#Sunset47".toCharArray(), loaded.getPasswordHash()));
    }

    @Test
    void noPlainPasswordOnDisk() throws IOException {
        users(integrity).add(new User("ghost1473",
                TestHashers.fast().hash("Kariba#Sunset47".toCharArray()), NOW));
        String content = Files.readString(dir.resolve("users.txt"), StandardCharsets.UTF_8);
        assertFalse(content.contains("Kariba#Sunset47"));
        assertTrue(content.contains("pbkdf2-sha256$"));
    }

    @Test
    void ledgerSurvivesRestartAndVerifies() {
        seedLedger();
        FileAccountRepository accounts = accounts();
        FileTransactionRepository txs = transactions();
        LedgerVerifier.verify(accounts, txs);
        assertEquals(new BigDecimal("75.00"), accounts.findByNumber(ACC).orElseThrow().getBalance());
        assertEquals(3, txs.findByAccount(ACC).size());
    }

    // ---------- HMAC ----------

    @Test
    void editedFileIsRejectedByHmac() throws IOException {
        seedLedger();
        editRaw("accounts.txt", "|75.00|", "|99075.00|");
        DataIntegrityException e = assertThrows(DataIntegrityException.class, this::accounts);
        assertTrue(e.getMessage().contains("HMAC"));
    }

    @Test
    void fileSignedWithAnotherKeyIsRejected() {
        seedLedger();
        byte[] other = new byte[32];
        other[0] = 1;
        IntegrityService wrongKey = IntegrityService.withKey(other);
        assertThrows(DataIntegrityException.class,
                () -> new FileAccountRepository(file("accounts.txt", FileAccountRepository.HEADER, wrongKey)));
    }

    @Test
    void trustOnFirstUseAcceptsOnceThenReSigns() throws IOException {
        users(integrity).add(new User("ghost1473",
                TestHashers.fast().hash("Kariba#Sunset47".toCharArray()), NOW));
        byte[] fresh = new byte[32];
        fresh[5] = 9;
        IntegrityService newKey = IntegrityService.withKey(fresh);
        assertThrows(DataIntegrityException.class, () -> users(newKey)); // not trusted yet

        newKey.trustUnsignedFiles();
        users(newKey); // accepted and re-signed with the new key
        assertTrue(users(IntegrityService.withKey(fresh)).findByUsername("ghost1473").isPresent());
    }

    // ---------- hash chain (attacker HAS the key) ----------

    @Test
    void alteredTransactionBreaksChain() throws IOException {
        seedLedger();
        List<String> recs = recordLines("transactions.txt");
        recs.set(1, recs.get(1).replace("|30.00|", "|3.00|"));
        rewriteSigned("transactions.txt", FileTransactionRepository.HEADER, recs);
        DataIntegrityException e = assertThrows(DataIntegrityException.class, this::transactions);
        assertTrue(e.getMessage().contains("altered"));
    }

    @Test
    void deletedTransactionBreaksChain() throws IOException {
        seedLedger();
        List<String> recs = recordLines("transactions.txt");
        recs.remove(1);
        rewriteSigned("transactions.txt", FileTransactionRepository.HEADER, recs);
        DataIntegrityException e = assertThrows(DataIntegrityException.class, this::transactions);
        assertTrue(e.getMessage().contains("chain broken"));
    }

    @Test
    void reorderedTransactionsBreakChain() throws IOException {
        seedLedger();
        List<String> recs = recordLines("transactions.txt");
        recs.add(0, recs.remove(2));
        rewriteSigned("transactions.txt", FileTransactionRepository.HEADER, recs);
        assertThrows(DataIntegrityException.class, this::transactions);
    }

    // ---------- reconciliation ----------

    @Test
    void balanceThatDoesNotMatchHistoryIsDetected() throws IOException {
        seedLedger();
        List<String> recs = recordLines("accounts.txt");
        recs.set(0, recs.get(0).replace("|75.00|", "|5000.00|"));
        rewriteSigned("accounts.txt", FileAccountRepository.HEADER, recs);
        FileAccountRepository accounts = accounts(); // HMAC is valid this time...
        FileTransactionRepository txs = transactions();
        assertThrows(DataIntegrityException.class, () -> LedgerVerifier.verify(accounts, txs)); // ...but the books don't balance
    }

    @Test
    void accountNumbersAreMaskedInMessages() {
        assertEquals("******0005", LedgerVerifier.mask(ACC));
    }

    // ---------- malformed records ----------

    @Test
    void malformedRecordsAreRejectedWithLineNumber() throws IOException {
        List<String> bad = List.of(
                "6200000005|ghost1473|abc|2026-10-08T08:00:00Z",     // bad amount
                "6200000005|ghost1473|-5.00|2026-10-08T08:00:00Z",   // negative balance
                "6200000005|ghost1473|5.00",                         // missing field
                "6200000005|bad|name|5.00|2026-10-08T08:00:00Z",     // injected separator
                "6200000006|ghost1473|5.00|2026-10-08T08:00:00Z");   // bad check digit
        for (String record : bad) {
            rewriteSigned("accounts.txt", FileAccountRepository.HEADER, List.of(record));
            DataIntegrityException e = assertThrows(DataIntegrityException.class, this::accounts);
            assertTrue(e.getMessage().contains("line 2"), e.getMessage());
        }
    }

    @Test
    void writerRefusesRecordsThatCouldInjectLines() {
        SignedDataFile f = file("accounts.txt", FileAccountRepository.HEADER, integrity);
        assertThrows(IllegalArgumentException.class, () -> f.writeLines(List.of("a\n#hmac=x")));
        assertThrows(IllegalArgumentException.class, () -> f.writeLines(List.of("#fake")));
    }

    // ---------- files and locking ----------

    @Test
    void atomicWriteLeavesNoTempFiles() throws IOException {
        seedLedger();
        try (Stream<Path> files = Files.list(dir)) {
            assertTrue(files.noneMatch(p -> p.toString().endsWith(".tmp")));
        }
    }

    @Test
    void secondInstanceCannotOpenDataFolder() throws IOException {
        Path data = dir.resolve("data");
        try (DataDirectory first = DataDirectory.open(data)) {
            assertThrows(BankException.class, () -> DataDirectory.open(data));
        }
        DataDirectory.open(data).close(); // free again once the first one closes
    }

    @Test
    void keyIsCreatedOnceThenReused() throws IOException {
        Path keyFile = dir.resolve(".secret.key");
        IntegrityService first = IntegrityService.loadOrCreate(keyFile);
        IntegrityService second = IntegrityService.loadOrCreate(keyFile);
        assertTrue(first.isNewKey());
        assertFalse(second.isNewKey());
        assertEquals(first.sign("hello"), second.sign("hello"));
    }

    @Test
    void emptyStartIsFine() {
        assertTrue(accounts().findAll().isEmpty()); // no files yet = no data, not an error
    }
}
