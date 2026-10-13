package securebank.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import securebank.exception.ValidationException;

class InputValidatorTest {

    @Test
    void usernameIsTrimmedAndLowerCased() {
        assertEquals("ghost1473", InputValidator.username("  Ghost1473 "));
    }

    @Test
    void invalidUsernamesAreRejected() {
        String[] bad = {null, "", "abc", "1ghost", "ghost|admin", "ghost\nadmin",
                        "ghost admin", "../etc/passwd", "a".repeat(21), "ghöst"};
        for (String name : bad) {
            assertThrows(ValidationException.class, () -> InputValidator.username(name));
        }
    }
}
