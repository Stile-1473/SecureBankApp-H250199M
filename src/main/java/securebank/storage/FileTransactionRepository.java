package securebank.storage;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import securebank.exception.DataIntegrityException;
import securebank.exception.StorageException;
import securebank.model.Transaction;
import securebank.model.TransactionType;
import securebank.repository.TransactionRepository;

/*
 * Stores transactions in a file and links each record to the previous one
 * using SHA-256 hashes. This helps detect changes to the transaction history,
 * such as edited, deleted, inserted, or reordered records
 * The file's integrity is also checked when the application starts
 */
public final class FileTransactionRepository implements TransactionRepository {

    public static final String HEADER = "# securebank transactions v1";
    static final String GENESIS = "0".repeat(64);

    // Holds a transaction together with its previous hash and current hash
    private record Entry(Transaction tx, String previousHash, String hash) {
    }

    private final SignedDataFile file;
    private final List<Entry> entries = new ArrayList<>();

    public FileTransactionRepository(SignedDataFile file) {
        this.file = Objects.requireNonNull(file, "file");
        List<String> lines = file.readLines();
        String previous = GENESIS;

        for (int i = 0; i < lines.size(); i++) {
            RecordCodec c = new RecordCodec(file.name(), i + 2);
            String[] f = c.split(lines.get(i), 8);
            Transaction tx = parse(f, c);

            // Make sure this record points to the hash of the previous transaction
            if (!f[6].equals(previous)) {
                throw c.bad("hash chain broken (a record was removed, inserted or reordered)", null);
            }

            // Recalculate the hash and compare it with the one saved in the file
            String expected = hash(previous, tx);
            if (!MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII),
                    f[7].getBytes(StandardCharsets.US_ASCII))) {
                throw c.bad("hash mismatch (the record was altered)", null);
            }

            entries.add(new Entry(tx, previous, expected));
            previous = expected;
        }

        if (file.acceptedUnsigned()) {
            save();
        }
    }

    @Override
    public synchronized void append(Transaction tx) {
        Objects.requireNonNull(tx, "transaction");

        // Link the new transaction to the last record in the chain
        String previous = entries.isEmpty() ? GENESIS : entries.get(entries.size() - 1).hash();
        entries.add(new Entry(tx, previous, hash(previous, tx)));

        try {
            save();
        } catch (StorageException e) {
            // Remove the new entry from memory if saving it fails
            entries.remove(entries.size() - 1);
            throw e;
        }
    }

    @Override
    public synchronized List<Transaction> findByAccount(String accountNumber) {
        return entries.stream()
                .map(Entry::tx)
                .filter(t -> t.accountNumber().equals(accountNumber))
                .toList();
    }

    // Returns the hash of the last transaction or the starting hash if empty
    public synchronized String headHash() {
        return entries.isEmpty() ? GENESIS : entries.get(entries.size() - 1).hash();
    }

    // Writes the transaction history including each record's hash information
    private void save() {
        List<String> lines = new ArrayList<>();

        for (Entry e : entries) {
            lines.add(canonical(e.tx()) + RecordCodec.SEP + e.previousHash() + RecordCodec.SEP + e.hash());
        }

        try {
            file.writeLines(lines);
        } catch (IOException e) {
            throw new StorageException(e);
        }
    }

    /*
     * Builds a consistent string from a transaction's fields before hashing
     * Keeping the field order and format consistent allows the hash to be
     * checked again when the file is loaded
     */
    private static String canonical(Transaction t) {
        return String.join(RecordCodec.SEP, t.id(), t.accountNumber(), t.type().name(),
                t.amount().toPlainString(), t.balanceAfter().toPlainString(), t.timestamp().toString());
    }

    // Creates a SHA-256 hash using the previous hash and current transaction
    static String hash(String previousHash, Transaction tx) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] digest = sha.digest((previousHash + RecordCodec.SEP + canonical(tx))
                    .getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    // Converts a saved transaction record into a Transaction object
    private static Transaction parse(String[] f, RecordCodec c) {
        try {
            return new Transaction(f[0], f[1], TransactionType.valueOf(f[2]),
                    c.parseMoney(f[3]), c.parseMoney(f[4]), c.parseInstant(f[5]));
        } catch (DataIntegrityException e) {
            throw e;
        } catch (RuntimeException e) {
            throw c.bad("invalid transaction record", e);
        }
    }
}