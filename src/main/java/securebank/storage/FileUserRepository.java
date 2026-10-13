package securebank.storage;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import securebank.exception.DataIntegrityException;
import securebank.exception.StorageException;
import securebank.model.User;
import securebank.repository.UserRepository;
import securebank.security.PasswordHash;

/*
 * Stores user details in users.txt, with one user per line
 * Each record contains the username, encoded password hash, account creation
 * time, failed login attempts and the time the account unlocks, if locked
 *
 * Plain-text passwords are never saved to the file. Failed login attempts and
 * account lock information are also saved, so restarting the application
 * does not reset the protection against repeated login attempts
 */
public final class FileUserRepository implements UserRepository {

    public static final String HEADER = "# securebank users v1";
    private static final String NONE = "-";

    private final SignedDataFile file;
    private final Map<String, User> users = new LinkedHashMap<>();

    public FileUserRepository(SignedDataFile file) {
        this.file = Objects.requireNonNull(file, "file");
        List<String> lines = file.readLines();

        for (int i = 0; i < lines.size(); i++) {
            User user = parse(lines.get(i), new RecordCodec(file.name(), i + 2));

            // Duplicate usernames are not allowed in the stored user records
            if (users.putIfAbsent(user.getUsername(), user) != null) {
                throw new DataIntegrityException(
                        file.name() + ": duplicate user " + user.getUsername() + ".");
            }
        }

        // Rewrite the file using the current signed format if it was accepted
        // in the older unsigned format
        if (file.acceptedUnsigned()) {
            save();
        }
    }

    @Override
    public synchronized Optional<User> findByUsername(String username) {
        // A null username cannot match a stored user
        return Optional.ofNullable(username == null ? null : users.get(username));
    }

    @Override
    public synchronized boolean add(User user) {
        Objects.requireNonNull(user, "user");

        // Do not overwrite an account that already uses this username
        if (users.putIfAbsent(user.getUsername(), user) != null) {
            return false;
        }

        try {
            save();
        } catch (StorageException e) {
            // Undo the in-memory change if saving fails, keeping memory and
            // the stored user records consistent as far as possible
            users.remove(user.getUsername());
            throw e;
        }

        return true;
    }

    @Override
    public synchronized void update(User user) {
        Objects.requireNonNull(user, "user");

        // Only existing accounts can be updated through this method
        if (!users.containsKey(user.getUsername())) {
            throw new IllegalStateException("Cannot update a user that does not exist");
        }

        users.put(user.getUsername(), user);
        save();
    }

    // Writes all current user records to the signed data file
    private void save() {
        List<String> lines = new ArrayList<>();

        for (User u : users.values()) {
            lines.add(String.join(RecordCodec.SEP,
                    u.getUsername(),
                    u.getPasswordHash().encode(),
                    u.getCreatedAt().toString(),
                    String.valueOf(u.getFailedAttempts()),
                    u.getLockedUntil() == null ? NONE : u.getLockedUntil().toString()));
        }

        try {
            file.writeLines(lines);
        } catch (IOException e) {
            throw new StorageException(e);
        }
    }

    // Converts a saved user record back into a User object
    private static User parse(String line, RecordCodec c) {
        String[] f = c.split(line, 5);

        try {
            // A dash means the account is not currently locked
            Instant lockedUntil = NONE.equals(f[4]) ? null : c.parseInstant(f[4]);

            return new User(f[0], PasswordHash.decode(f[1]), c.parseInstant(f[2]),
                    c.parseInt(f[3]), lockedUntil);
        } catch (DataIntegrityException e) {
            throw e;
        } catch (RuntimeException e) {
            // The record could not be used to create a valid User object
            throw c.bad("invalid user record", e);
        }
    }
}