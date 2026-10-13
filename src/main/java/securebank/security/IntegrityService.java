package securebank.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import securebank.exception.DataIntegrityException;
import securebank.storage.SecureFiles;

/*
 * Signs and checks data files using HMAC-SHA256
 *
 * A normal SHA-256 hash is not enough, someone could edit a file and calculate a new hash
 * HMAC uses a secret key stored in its own protected file, and that key should never be committed to Git
 * This helps detect changes made by someone who doesnt have the key
 */
public final class IntegrityService {

    private static final String ALGORITHM = "HmacSHA256";
    private static final int KEY_BYTES = 32;

    private final SecretKeySpec key;
    private final boolean newKey;
    private boolean trustUnsignedFiles;

    private IntegrityService(byte[] keyBytes, boolean newKey) {
        this.key = new SecretKeySpec(keyBytes, ALGORITHM);
        this.newKey = newKey;
    }

    /** Loads the existing key or creates a new random one on the first run */
    public static IntegrityService loadOrCreate(Path keyFile) throws IOException {
        if (Files.exists(keyFile)) {
            byte[] keyBytes;

            try {
                keyBytes = Base64.getDecoder().decode(
                        Files.readString(keyFile, StandardCharsets.UTF_8).strip()
                );
            } catch (IllegalArgumentException e) {
                throw new DataIntegrityException("The integrity key file is corrupt.", e);
            }

            if (keyBytes.length != KEY_BYTES) {
                throw new DataIntegrityException("The integrity key file is corrupt.");
            }

            return new IntegrityService(keyBytes, false);
        }

        byte[] keyBytes = new byte[KEY_BYTES];
        new SecureRandom().nextBytes(keyBytes);

        SecureFiles.writeAtomically(
                keyFile,
                Base64.getEncoder().encodeToString(keyBytes) + "\n"
        );

        return new IntegrityService(keyBytes, true);
    }

    /** Creates a service with a known key for testing */
    public static IntegrityService withKey(byte[] keyBytes) {
        return new IntegrityService(keyBytes.clone(), false);
    }

    /** Returns true if a new key was created during this run */
    public boolean isNewKey() {
        return newKey;
    }

    /*
     * Trust on first use, this should only happen after someone at the console agrees to accept unsigned data files
     * Otherwise, deleting the key file could become an easy way to bypass the integrity checks
     */
    public void trustUnsignedFiles() {
        this.trustUnsignedFiles = true;
    }

    public boolean isTrustingUnsignedFiles() {
        return trustUnsignedFiles;
    }

    public String sign(String content) {
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(key);

            return Base64.getEncoder().encodeToString(
                    mac.doFinal(content.getBytes(StandardCharsets.UTF_8))
            );
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC is unavailable", e);
        }
    }

    /** Compares the expected and supplied signatures without a normal early-exit comparison */
    public boolean verify(String content, String signature) {
        if (signature == null) {
            return false;
        }

        byte[] expected = sign(content).getBytes(StandardCharsets.UTF_8);
        byte[] actual = signature.getBytes(StandardCharsets.UTF_8);

        return MessageDigest.isEqual(expected, actual);
    }
}