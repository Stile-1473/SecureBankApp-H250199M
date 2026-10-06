package securebank.security;

import java.util.Arrays;
import java.util.Base64;

public class PasswordHash {
    private static final String PREFIX = "pbkdf2-sha256";
    private static final int MIN_ITERATIONS = 1;
    private static final int MAX_ITERATIONS = 10_000_000;


    private final byte[] salt;
    private final byte[] hash;
    private final int iterations;

    public PasswordHash(byte[] salt, byte[] hash, int iterations) {


        if (salt == null || salt.length < 16){
            throw new IllegalArgumentException("Salt must be at least 16 bytes");
        }


        if(hash == null || hash.length < 32){
            throw new IllegalArgumentException("Hash must be at least 32 bytes");
        }

        if(iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS){
            throw new IllegalArgumentException("Iterations must be between " + MIN_ITERATIONS + " and " + MAX_ITERATIONS);
        }

        this.salt = salt.clone();
        this.hash = hash.clone();
        this.iterations = iterations;
    }



    public byte[] salt(){
        return salt.clone();
    }

    public byte[] hash(){
        return hash.clone();
    }

    public int iterations() {
        return iterations;
    }
    /*
    Serialises this credential for storage in users.txt
     */

    public  String encode(){
        Base64.Encoder b64 = Base64.getEncoder();
        return PREFIX + "$$" + iterations + "$$" + b64.encodeToString(salt) + "$$" + b64.encodeToString(hash);
    }

    /*
    Parses a stored credential
    Aynting malformed will be rejected
     */

    public  static PasswordHash decode(String encoded){
        if (encoded == null){
            throw new IllegalArgumentException("Missing password hash");
        }

        String[] parts  = encoded.split("\\$", -1);
        if (parts.length != 4 || !PREFIX.equals(parts[0])){
            throw new IllegalArgumentException("Unrecognised password hash format");
        }

        try{
            int iterations = Integer.parseInt(parts[1]);
            Base64.Decoder b64 = Base64.getDecoder();
            return new PasswordHash(b64.decode(parts[2]), b64.decode(parts[3]),iterations);

        }catch (IllegalArgumentException e){
            throw new IllegalArgumentException("Corrupt password hash,",e);
        }
    }


    @Override
    public boolean equals(Object o) {
        if(this == o){
            return  true;
        }

        if (!(o instanceof  PasswordHash other)){
            return false;
        }

        return iterations == other.iterations
                && Arrays.equals(salt,other.salt)
                && Arrays.equals(hash,other.hash);
    }

    @Override
    public int hashCode() {
        return 31 * Arrays.hashCode(hash) + iterations;
    }

    @Override
    public String toString() {
        return "PasswordHarsh[" + PREFIX + ", iterations" + iterations + "]";
    }



}
