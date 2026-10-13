package securebank.exception;

/**
 * Login failed. Always carries the same generic message, whatever the real reason
 * (unknown user, wrong password, locked account), so attackers learn nothing.
 */
public class AuthenticationException extends BankException {

    private static final long serialVersionUID = 1L;

    public AuthenticationException(String message) {
        super(message);
    }
}
