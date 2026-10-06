package securebank.security;


import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/*
This verifies passwords with PBKDF2-HMAC-SHA256
 */
public class PasswordHasher {

    public static final int DEFAULT_ITERATIONS = 600_000;

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int SALT_BYTES= 16;
    private static final int KEY_BITS = 256;

    private final SecureRandom random = new SecureRandom();
    private final int iterations;
    private final PasswordHash dummyHash;

    public PasswordHasher() {
        this(DEFAULT_ITERATIONS);
    }

    PasswordHasher(int iterations) {
        if(iterations < 1 ){
            throw  new IllegalArgumentException("Iterations must be at postive");
        }

        this.iterations = iterations;

        //used to spend the same time on unkown usernames
        this.dummyHash = hash("dummy-password-for-timing".toCharArray());}


    //Creates a new salted hash
    public  PasswordHash hash(char[] password){
        requirePassword(password);
        byte[] salt =  new byte[SALT_BYTES];
        random.nextBytes(salt);
        byte[] derived = derive(password,salt,iterations);


        try{
            return new PasswordHash(salt,derived,iterations);

        }finally {
            Arrays.fill(derived,(byte) 0 );
        }

    }


    /* Returns true only if {@code password} matches {@code stored}. Constant-time comparison. */

    public boolean verify(char[] password,PasswordHash stored){
        requirePassword(password);
        if(stored == null){
            throw new IllegalArgumentException("Stored password hash cannot be null");
        }

        byte[] candidate  = derive(password,stored.salt(),stored.iterations());
        byte[] expected = stored.hash();

        try{
            return MessageDigest.isEqual(candidate,expected);
        }finally {
            Arrays.fill(candidate,(byte) 0 );
            Arrays.fill(expected,(byte) 0);
        }
    }


    private boolean needsRehash(PasswordHash stored){
        return stored.iterations() < iterations;

    }

    private  static void requirePassword(char[] password){
        if(password == null || password.length == 0){
            throw new IllegalArgumentException("Password cannot be null or empty");
        }
    }

    private static byte[] derive(char[] password, byte[] salt, int iterations){
        PBEKeySpec spec =  new PBEKeySpec(password,salt,iterations,KEY_BITS);

        try{
            return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();

        }catch (NoSuchAlgorithmException | InvalidKeySpecException e){
            //never fallls back to a weaker algorithm
            throw new IllegalArgumentException("Password hashing is unavailable",e);
        }finally {
            spec.clearPassword();
        }
    }
}
