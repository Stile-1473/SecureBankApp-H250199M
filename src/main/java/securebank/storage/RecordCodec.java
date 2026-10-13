package securebank.storage;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import securebank.exception.DataIntegrityException;

/*
 * Handles splitting saved records into fields and converting those fields
 * into the correct data types. If a record contains invalid data, the error
 * includes the file name and line number to help identify the problem
 *
 * This helps prevent corrupted records from being loaded silently
 * The fields written by the application use controlled formats, such as
 * usernames, account numbers, Base64 strings, numbers and ISO timestamps,
 * which do not contain the record separator or newline characters
 */
final class RecordCodec {

    static final String SEP = "|";

    private final String fileName;
    private final int lineNumber;

    RecordCodec(String fileName, int lineNumber) {
        this.fileName = fileName;
        this.lineNumber = lineNumber;
    }

    // Splits a record and checks that it contains the expected number of fields
    String[] split(String line, int expectedFields) {
        String[] f = line.split("\\|", -1);

        if (f.length != expectedFields) {
            throw bad("wrong number of fields", null);
        }

        return f;
    }

    // Converts a field to an integer and reports a clear error if it is invalid
    int parseInt(String s) {
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            throw bad("invalid number", e);
        }
    }

    // Converts a field to a monetary amount
    BigDecimal parseMoney(String s) {
        try {
            return new BigDecimal(s);
        } catch (NumberFormatException e) {
            throw bad("invalid amount", e);
        }
    }

    // Converts a field to an Instant using the expected timestamp format
    Instant parseInstant(String s) {
        try {
            return Instant.parse(s);
        } catch (DateTimeParseException e) {
            throw bad("invalid timestamp", e);
        }
    }

    // Creates a data integrity error that identifies where the problem occurred
    DataIntegrityException bad(String what, Throwable cause) {
        return new DataIntegrityException(
                fileName + " line " + lineNumber + ": " + what + ".", cause);
    }
}