package securebank.exception;

/** A withdrawal would take the balance below zero. */
public class InsufficientFundsException extends BankException {

    private static final long serialVersionUID = 1L;

    public InsufficientFundsException() {
        super("Insufficient funds.");
    }
}
