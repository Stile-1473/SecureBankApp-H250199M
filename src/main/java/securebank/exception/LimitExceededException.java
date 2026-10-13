package securebank.exception;

/** A transaction breaks a business limit (per-transaction, daily, or account count). */
public class LimitExceededException extends BankException {

    private static final long serialVersionUID = 1L;

    public LimitExceededException(String message) {
        super(message);
    }
}
