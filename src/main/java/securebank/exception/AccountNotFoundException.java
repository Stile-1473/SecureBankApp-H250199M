package securebank.exception;

/**
 * Thrown both when an account doesn't exist AND when it belongs to someone else.
 * Using one message for both means users can't discover other people's account numbers.
 */
public class AccountNotFoundException extends BankException {

    private static final long serialVersionUID = 1L;

    public AccountNotFoundException() {
        super("Account not found.");
    }
}
