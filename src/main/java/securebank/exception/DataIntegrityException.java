package securebank.exception;

/**
 * A data file failed an integrity check: wrong HMAC, broken hash chain, malformed
 * record, or balances that don't match the transaction history. The application
 * refuses to start rather than run on data it can't trust (fail secure).
 */
public class DataIntegrityException extends BankException {

    private static final long serialVersionUID = 1L;

    public DataIntegrityException(String message) {
        super(message);
    }

    public DataIntegrityException(String message, Throwable cause) {
        super(message, cause);
    }
}
