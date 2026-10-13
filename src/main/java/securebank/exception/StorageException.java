package securebank.exception;

/** Saving to disk failed (disk full, permissions, etc.). */
public class StorageException extends BankException {

    private static final long serialVersionUID = 1L;

    public StorageException(Throwable cause) {
        super("Could not save your changes. Please try again.", cause);
    }
}
