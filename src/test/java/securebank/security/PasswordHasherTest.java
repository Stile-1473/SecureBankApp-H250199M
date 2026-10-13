package securebank.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class PasswordHasherTest {

    // Low work factor keeps tests fast; production uses DEFAULT_ITERATIONS.
    private final PasswordHasher hasher = new PasswordHasher(1_000);

    @Test
    void correctPasswordVerifies() {
        PasswordHash stored = hasher.hash("Kariba#Sunset47".toCharArray());
        assertTrue(hasher.verify("Kariba#Sunset47".toCharArray(), stored));
    }

    @Test
    void wrongPasswordIsRejected() {
        PasswordHash stored = hasher.hash("Kariba#Sunset47".toCharArray());
        assertFalse(hasher.verify("Kariba#Sunset48".toCharArray(), stored));
    }

    @Test
    void samePasswordGetsDifferentSaltAndHash() {
        PasswordHash a = hasher.hash("Kariba#Sunset47".toCharArray());
        PasswordHash b = hasher.hash("Kariba#Sunset47".toCharArray());
        assertNotEquals(a.encode(), b.encode());
    }

    @Test
    void encodeDecodeRoundTripStillVerifies() {
        PasswordHash stored = hasher.hash("Kariba#Sunset47".toCharArray());
        PasswordHash loaded = PasswordHash.decode(stored.encode());
        assertEquals(stored, loaded);
        assertTrue(hasher.verify("Kariba#Sunset47".toCharArray(), loaded));
    }

    @Test
    void tamperedHashFailsVerification() {
        PasswordHash stored = hasher.hash("Kariba#Sunset47".toCharArray());
        byte[] hash = stored.hash();
        hash[0] ^= 1; // flip one bit
        PasswordHash tampered = new PasswordHash(stored.salt(), hash, stored.iterations());
        assertFalse(hasher.verify("Kariba#Sunset47".toCharArray(), tampered));
    }

    @Test
    void malformedStoredHashIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> PasswordHash.decode("plaintext-password"));
        assertThrows(IllegalArgumentException.class, () -> PasswordHash.decode("pbkdf2-sha256$abc$x$y"));
        assertThrows(IllegalArgumentException.class, () -> PasswordHash.decode(null));
    }

    @Test
    void weakerWorkFactorNeedsRehash() {
        PasswordHash old = new PasswordHasher(500).hash("Kariba#Sunset47".toCharArray());
        assertTrue(hasher.needsRehash(old));
        assertFalse(hasher.needsRehash(hasher.hash("Kariba#Sunset47".toCharArray())));
    }

    @Test
    void dummyVerifyAlwaysFails() {
        assertFalse(hasher.dummyVerify("anything".toCharArray()));
    }

    @Test
    void emptyPasswordIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> hasher.hash(new char[0]));
    }

    @Test
    void toStringDoesNotLeakSecrets() {
        PasswordHash stored = hasher.hash("Kariba#Sunset47".toCharArray());
        assertFalse(stored.toString().contains(stored.encode().split("\\$")[3]));
    }
}
