package securebank;

import java.io.Console;

/**
 * Entry point for the Secure Banking Application.
 */
public final class App {

    private App() {
        // Not instantiable.
    }

    public static void main(String[] args) {
        Console console = System.console();
        if (console == null) {
            // Without a real terminal, passwords would echo on screen.
            System.err.println("No secure console detected. Run from a terminal: java -jar target/securebank.jar");
            System.exit(1);
        }
        console.printf("=== Secure Banking Application ===%n");
        console.printf("Setup OK. Java %s%n", System.getProperty("java.version"));
    }
}
