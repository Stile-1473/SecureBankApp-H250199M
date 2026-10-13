package securebank.storage;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import securebank.exception.BankException;

/*
 * Manages the folder where the application stores its data
 * It uses a file lock to prevent multiple copies of the application
 * from accessing the same data folder at the same time
 * The lock is released when the application closes
 */
public final class DataDirectory implements AutoCloseable {

    private final Path root;
    private final FileChannel lockChannel;
    private final FileLock lock;

    private DataDirectory(Path root, FileChannel lockChannel, FileLock lock) {
        this.root = root;
        this.lockChannel = lockChannel;
        this.lock = lock;
    }

    public static DataDirectory open(Path root) throws IOException {
        Files.createDirectories(root);
        SecureFiles.restrictDirectory(root);
        Path lockFile = root.resolve(".lock");
        FileChannel channel = FileChannel.open(lockFile, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        SecureFiles.restrictFile(lockFile);
        FileLock lock;
        try {
            lock = channel.tryLock();
        } catch (OverlappingFileLockException e) {
            lock = null; // already locked by this same program
        }
        if (lock == null) {
            channel.close();
            throw new BankException("Another copy of the application is already running.");
        }
        return new DataDirectory(root, channel, lock);
    }

    /*
     * Returns the path to a file inside the data folder
     * File names are defined by the application rather than entered by user
     */
    public Path file(String name) {
        return root.resolve(name);
    }

    @Override
    public void close() throws IOException {
        lock.release();
        lockChannel.close();
    }
}
