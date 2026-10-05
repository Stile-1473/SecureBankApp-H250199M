package securebank.exception;


/*
This is the base type for all the application errors
Messages will be safe to show to the user
They will not contain secrets,hashes or stack trace details or files
 */
public class BankException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public BankException(String message){
        super(message);
    }

    public BankException(String message,Throwable cause){
        super(message,cause);
    }
}
