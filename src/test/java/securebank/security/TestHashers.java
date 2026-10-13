package securebank.security;

/**
 * Test helper. Lives in the securebank.security test package so it can reach
 * PasswordHasher's package-private constructor and hand out fast hashers.
 */
public final class TestHashers {

    private TestHashers() {
    }

    public static PasswordHasher fast() {
        return new PasswordHasher(1_000);
    }

    public static PasswordHasher withIterations(int iterations) {
        return new PasswordHasher(iterations);
    }
}
