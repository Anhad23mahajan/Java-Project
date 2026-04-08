package vaultmind.service;

import vaultmind.model.User;
import vaultmind.model.VaultFile;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;

public class DatabaseManager {

    private static final String URL = System.getenv().getOrDefault(
            "VAULTMIND_DB_URL",
            "jdbc:postgresql://localhost:5432/vaultmind"
    );
    private static final String USER = System.getenv().getOrDefault(
            "VAULTMIND_DB_USER",
            "postgres"
    );
    private static final String PASSWORD = System.getenv().getOrDefault(
            "VAULTMIND_DB_PASSWORD",
            "postgres"
    );

    public static Connection getConnection() throws SQLException {
        try {
            Class.forName("org.postgresql.Driver");
        } catch (ClassNotFoundException e) {
            throw new SQLException("PostgreSQL JDBC driver not found. Add the PostgreSQL JDBC jar to the classpath.", e);
        }
        return DriverManager.getConnection(URL, USER, PASSWORD);
    }

    public static boolean addUser(String username, String passwordHash, String role) throws SQLException {
        String sql = "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)";
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, username);
            stmt.setString(2, passwordHash);
            stmt.setString(3, role);
            stmt.executeUpdate();
            return true;
        }
    }

    public static User getUserByUsername(String username) throws SQLException {
        String sql = "SELECT user_id, username, password_hash, role, created_at FROM users WHERE username = ?";
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return mapUser(rs);
            }
        }
        return null;
    }

    public static User getUserById(int userId) throws SQLException {
        String sql = "SELECT user_id, username, password_hash, role, created_at FROM users WHERE user_id = ?";
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, userId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return mapUser(rs);
            }
        }
        return null;
    }

    public static String hashPassword(String password) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(password.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            return null;
        }
    }

    public static List<User> getAllUsers() throws SQLException {
        List<User> users = new ArrayList<>();
        String sql = "SELECT user_id, username, password_hash, role, created_at FROM users ORDER BY created_at DESC";
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                users.add(mapUser(rs));
            }
        }
        return users;
    }

    public static boolean addFile(int userId, String fileName, String encryptedPath, byte[] fileContent) throws SQLException {
        String sql = "INSERT INTO vault_files (user_id, file_name, encrypted_path, file_content) VALUES (?, ?, ?, ?)";
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, userId);
            stmt.setString(2, fileName);
            stmt.setString(3, encryptedPath);
            stmt.setBytes(4, fileContent);
            stmt.executeUpdate();
            return true;
        }
    }

    public static VaultFile getFileByIdForUser(int fileId, int userId) throws SQLException {
        String sql = "SELECT vf.file_id, vf.user_id, u.username, vf.file_name, vf.encrypted_path, vf.file_content, vf.uploaded_at " +
                "FROM vault_files vf JOIN users u ON u.user_id = vf.user_id " +
                "WHERE vf.file_id = ? AND vf.user_id = ?";
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, fileId);
            stmt.setInt(2, userId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return mapVaultFile(rs);
            }
        }
        return null;
    }

    public static List<VaultFile> getFilesByUser(int userId) throws SQLException {
        List<VaultFile> files = new ArrayList<>();
        String sql = "SELECT vf.file_id, vf.user_id, u.username, vf.file_name, vf.encrypted_path, vf.file_content, vf.uploaded_at " +
                "FROM vault_files vf JOIN users u ON u.user_id = vf.user_id " +
                "WHERE vf.user_id = ? ORDER BY vf.uploaded_at DESC";
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, userId);
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                files.add(mapVaultFile(rs));
            }
        }
        return files;
    }

    public static List<VaultFile> getAllFiles() throws SQLException {
        List<VaultFile> files = new ArrayList<>();
        String sql = "SELECT vf.file_id, vf.user_id, u.username, vf.file_name, vf.encrypted_path, vf.file_content, vf.uploaded_at " +
                "FROM vault_files vf JOIN users u ON u.user_id = vf.user_id " +
                "ORDER BY vf.uploaded_at DESC";
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                files.add(mapVaultFile(rs));
            }
        }
        return files;
    }

    public static void bootstrapAdminFromEnv() throws SQLException {
        String bootstrap = System.getenv().getOrDefault("VAULTMIND_BOOTSTRAP_ADMIN", "false");
        if (!"true".equalsIgnoreCase(bootstrap)) {
            return;
        }

        String adminUsername = System.getenv().getOrDefault("VAULTMIND_ADMIN_USERNAME", "admin");
        String adminPassword = System.getenv("VAULTMIND_ADMIN_PASSWORD");

        if (adminPassword == null || adminPassword.isBlank()) {
            throw new SQLException("VAULTMIND_ADMIN_PASSWORD must be set when VAULTMIND_BOOTSTRAP_ADMIN=true");
        }

        User existingUser = getUserByUsername(adminUsername);
        if (existingUser == null) {
            addUser(adminUsername, hashPassword(adminPassword), "admin");
        }
    }

    private static User mapUser(ResultSet rs) throws SQLException {
        Timestamp createdAt = rs.getTimestamp("created_at");
        return new User(
                rs.getInt("user_id"),
                rs.getString("username"),
                rs.getString("password_hash"),
                rs.getString("role"),
                createdAt == null ? "" : createdAt.toLocalDateTime().toString()
        );
    }

    private static VaultFile mapVaultFile(ResultSet rs) throws SQLException {
        Timestamp uploadedAt = rs.getTimestamp("uploaded_at");
        return new VaultFile(
                rs.getInt("file_id"),
                rs.getInt("user_id"),
                rs.getString("username"),
                rs.getString("file_name"),
                rs.getString("encrypted_path"),
                rs.getBytes("file_content"),
                uploadedAt == null ? "" : uploadedAt.toLocalDateTime().toString()
        );
    }
}
