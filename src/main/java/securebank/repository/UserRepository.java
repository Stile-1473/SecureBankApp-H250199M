package securebank.repository;

import java.util.Optional;
import securebank.model.User;

/*
 * Handles storing and finding users
 * The rest of the app uses this interface instead of depending on a specific storage method
 * This makes it easier to switch from in-memory storage to file storage without changing the business logic
 */
public interface UserRepository {

    /* Finds a user using their normalised lower-case username */
    Optional<User> findByUsername(String username);

    /*
     * Adds a new user and returns false if the username is already taken
     * Checking and inserting must happen as one atomic step so two registrations cant use the same username
     */
    boolean add(User user);

    /** Saves changes to an existing user, like updating the failed login counter */
    void update(User user);
}