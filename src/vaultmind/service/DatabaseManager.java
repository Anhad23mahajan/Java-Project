package vaultmind.service;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class DatabaseManager {

    private static final String URL = "jdbc:mysql://localhost:3306/vaultmind";
    private static final String USER = "root";
    private static final String PASSWORD = "Anhad@14576";

    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(URL, USER, PASSWORD);
    }

    // Register a new user
    public static boolean addUser(String username, String passwordHash, String role) {
        String sql = "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)";
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, username);
            stmt.setString(2, passwordHash);
            stmt.setString(3, role);
            stmt.executeUpdate();
            System.out.println("User registered: " + username);
            return true;
        } catch (SQLException e) {
            System.out.println("Registration failed: " + e.getMessage());
            return false;
        }
    }

    // Get user by username
    public static String[] getUser(String username) {
        String sql = "SELECT user_id, username, password_hash, role FROM users WHERE username = ?";
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return new String[]{
                        String.valueOf(rs.getInt("user_id")),
                        rs.getString("username"),
                        rs.getString("password_hash"),
                        rs.getString("role")
                };
            }
        } catch (SQLException e) {
            System.out.println("Error fetching user: " + e.getMessage());
        }
        return null;
    }

    // Hash a password using SHA-256
    public static String hashPassword(String password) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(password.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            System.out.println("Hashing failed: " + e.getMessage());
            return null;
        }
    }

    // Get all users (admin only)
    public static void getAllUsers() {
        String sql = "SELECT user_id, username, role, created_at FROM users";
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            ResultSet rs = stmt.executeQuery();
            System.out.println("\n===== ALL USERS =====");
            while (rs.next()) {
                System.out.println("ID: " + rs.getInt("user_id") +
                        " | Username: " + rs.getString("username") +
                        " | Role: " + rs.getString("role") +
                        " | Joined: " + rs.getString("created_at"));
            }
            System.out.println("=====================");
        } catch (SQLException e) {
            System.out.println("Error fetching users: " + e.getMessage());
        }
    }

    // Add a file record to the database
    public static boolean addFile(int userId, String fileName, String encryptedPath) {
        String sql = "INSERT INTO vault_files (user_id, file_name, encrypted_path) VALUES (?, ?, ?)";
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, userId);
            stmt.setString(2, fileName);
            stmt.setString(3, encryptedPath);
            stmt.executeUpdate();
            System.out.println("File stored: " + fileName);
            return true;
        } catch (SQLException e) {
            System.out.println("Error storing file: " + e.getMessage());
            return false;
        }
    }

    // Get all files belonging to a user
    public static void getFilesByUser(int userId) {
        String sql = "SELECT file_id, file_name, encrypted_path, uploaded_at FROM vault_files WHERE user_id = ?";
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, userId);
            ResultSet rs = stmt.executeQuery();
            System.out.println("\n===== YOUR FILES =====");
            boolean hasFiles = false;
            while (rs.next()) {
                hasFiles = true;
                System.out.println("ID: " + rs.getInt("file_id") +
                        " | Name: " + rs.getString("file_name") +
                        " | Path: " + rs.getString("encrypted_path") +
                        " | Uploaded: " + rs.getString("uploaded_at"));
            }
            if (!hasFiles) {
                System.out.println("No files found.");
            }
            System.out.println("======================");
        } catch (SQLException e) {
            System.out.println("Error fetching files: " + e.getMessage());
        }
    }

    public static void testConnection() {
        try {
            Connection conn = getConnection();
            System.out.println("Connected to VaultMind database successfully!");
            conn.close();
        } catch (SQLException e) {
            System.out.println("Connection failed: " + e.getMessage());
        }
    }
}