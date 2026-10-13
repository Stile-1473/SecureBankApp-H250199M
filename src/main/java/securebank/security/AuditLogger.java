package securebank.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Clock;
import java.util.Objects;
import securebank.storage.SecureFiles;

/*
 * Keeps a record of important security events, who did what and when
 *
 * We dont log passwords, hashes or balances, and account numbers are masked
 * User input is cleaned so someone cant inject fake entries into the log
 * The file is append-only and gets restricted permissions
 *
 * If writing fails, the app keeps running and prints a warning once
 * A full disk shouldnt stop customers from accessing their money
 */
public final class AuditLogger {

    private static final int MAX_FIELD = 64;

    private final Path file;
    private final Clock clock;
    private boolean warned;

    private AuditLogger(Path file, Clock clock) {
        this.file = file;
        this.clock = clock;
    }

    /* Creates a logger for the given file */
    public static AuditLogger toFile(Path file, Clock clock) {
        return new AuditLogger(Objects.requireNonNull(file, "file"), Objects.requireNonNull(clock, "clock"));
    }

    /* Logger that ignores everything, useful for tests that dont check audit logging */
    public static AuditLogger disabled() {
        return new AuditLogger(null, Clock.systemUTC());
    }

    /*
     * Writes one audit entry with the time, event, user and any extra details
     * Event names should come from our code, and detail must never contain secrets
     */
    public synchronized void log(String event, String user, String detail) {
        if (file == null) {
            return;
        }

        String line = clock.instant() + " " + sanitise(event) + " user=" + sanitise(user)
                + (detail == null || detail.isEmpty() ? "" : " " + sanitise(detail)) + System.lineSeparator();

        try {
            Path dir = file.toAbsolutePath().getParent();
            if (!Files.isDirectory(dir)) {
                Files.createDirectories(dir);
                SecureFiles.restrictDirectory(dir);
            }

            Files.writeString(file, line, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            SecureFiles.restrictFile(file);
        } catch (IOException e) {
            if (!warned) {
                warned = true;
                System.err.println("Warning: the audit log could not be written.");
            }
        }
    }

    /*
     * Cleans each value and limits how much gets written
     * Newlines, tabs and other unsafe characters become underscores
     * This keeps someone from adding fake log entries using crafted input
     */
    static String sanitise(String value) {
        if (value == null) {
            return "-";
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < value.length() && sb.length() < MAX_FIELD; i++) {
            char c = value.charAt(i);
            boolean safe = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || " _.:=*-".indexOf(c) >= 0;
            sb.append(safe ? c : '_');
        }

        if (value.length() > MAX_FIELD) {
            sb.append("...");
        }

        return sb.length() == 0 ? "-" : sb.toString();
    }

    /* Hides all but the last four digits of an account number */
    public static String mask(String accountNumber) {
        if (accountNumber == null || accountNumber.length() < 4) {
            return "****";
        }

        int n = accountNumber.length();
        return "*".repeat(n - 4) + accountNumber.substring(n - 4);
    }
}