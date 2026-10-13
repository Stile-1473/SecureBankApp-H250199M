package securebank.exception;

/** The user's session timed out or was logged out. */
public class SessionExpiredException extends BankException {

    private static final long serialVersionUID = 1L;

    public SessionExpiredException() {
        super("Your session has expired. Please log in again.");
    }
}
