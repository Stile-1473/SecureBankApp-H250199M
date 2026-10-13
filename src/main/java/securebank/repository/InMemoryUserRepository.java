package securebank.repository;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import securebank.model.User;

/* Keeps users in memory for testing, a file-based version can be used later */
public final class InMemoryUserRepository implements UserRepository {

    private final Map<String, User> users = new ConcurrentHashMap<>();

    @Override
    public Optional<User> findByUsername(String username) {
        if (username == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(users.get(username));
    }

    @Override
    public boolean add(User user) {
        Objects.requireNonNull(user, "user");

        // Adds the user only if the username isnt already taken
        // putIfAbsent does both checks as one atomic step, so duplicate registrations cant slip through
        return users.putIfAbsent(user.getUsername(), user) == null;
    }

    @Override
    public void update(User user) {
        Objects.requireNonNull(user, "user");

        if (users.replace(user.getUsername(), user) == null) {
            throw new IllegalStateException("Cannot update a user that does not exist");
        }
    }
}