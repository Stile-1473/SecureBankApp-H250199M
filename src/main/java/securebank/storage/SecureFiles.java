package securebank.storage;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;

/*
 * Provides file operations for sensitive application data
 * Files are written using a temporary file before replacing the original,
 * and permissions are restricted so only the owner can access them
 */
public final class SecureFiles {

    private static final boolean POSIX =
            FileSystems.getDefault().supportedFileAttributeViews().contains("posix");

    private SecureFiles() {
    }

    /*
     * Writes the new content to a temporary file in the same directory,
     * forces the file contents to storage and then replaces the target file
     * This helps prevent a crash during writing from leaving the target file
     * only partially written
     */
    public static void writeAtomically(Path target, String content) throws IOException {
        Path dir = target.toAbsolutePath().getParent();
        Path tmp = Files.createTempFile(dir, target.getFileName().toString(), ".tmp");

        try {
            restrictFile(tmp);

            ByteBuffer buffer = ByteBuffer.wrap(content.getBytes(StandardCharsets.UTF_8));

            try (FileChannel channel = FileChannel.open(tmp, StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING)) {
                while (buffer.hasRemaining()) {
                    channel.write(buffer);
                }

                // Ask the operating system to flush the file's contents and metadata
                channel.force(true);
            }

            try {
                // Replace the target in one operation where the filesystem supports it
                Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                // Use a regular replacement if an atomic move is not supported
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            // Remove the temporary file if it was left behind after a failure
            Files.deleteIfExists(tmp);
        }

        // Apply the required permissions to the final file as well
        restrictFile(target);
    }

    /*
     * Sets file permissions to rw------- on POSIX systems
     * This allows the owner to read and write the file while denying
     * access to other users
     */
    public static void restrictFile(Path file) throws IOException {
        if (POSIX && Files.exists(file)) {
            Files.setPosixFilePermissions(file,
                    PosixFilePermissions.fromString("rw-------"));
        }
    }

    /*
     * Sets directory permissions to rwx------ on POSIX systems
     * Only the owner can list the directory, access its contents or enter it
     */
    public static void restrictDirectory(Path dir) throws IOException {
        if (POSIX && Files.isDirectory(dir)) {
            Files.setPosixFilePermissions(dir,
                    PosixFilePermissions.fromString("rwx------"));
        }
    }
}