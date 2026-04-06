package vaultmind.main;

import vaultmind.service.DatabaseManager;
import vaultmind.web.WebServer;

public class Main {
    public static void main(String[] args) {
        int port = Integer.parseInt(System.getenv().getOrDefault("VAULTMIND_PORT", "8080"));

        try {
            DatabaseManager.bootstrapAdminFromEnv();
            WebServer server = new WebServer("127.0.0.1", port);
            server.start();
            System.out.println("VaultMind web app is running at http://127.0.0.1:" + port);
            System.out.println("This server only listens on localhost.");
        } catch (Exception e) {
            System.err.println("Failed to start VaultMind: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
