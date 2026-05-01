package com.vaultmind;

import at.favre.lib.crypto.bcrypt.BCrypt;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.sql.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

// ABSTRACTION: Database Interface 
interface Database {
    void init() throws SQLException;
    int update(String sql, Object... params) throws SQLException;
    long insert(String sql, Object... params) throws SQLException;
    boolean exists(String sql, Object... params) throws SQLException;
    <T> T queryOne(String sql, DB.Mapper<T> mapper, Object... params) throws SQLException;
    <T> List<T> queryAll(String sql, DB.Mapper<T> mapper, Object... params) throws SQLException;
}
// INHERITANCE: PostgresDatabase implements Database 
final class PostgresDatabase implements Database {
    private static final String URL      = env("VAULTMIND_DB_URL",      "jdbc:postgresql://localhost:5432/vaultmind");
    private static final String USER     = env("VAULTMIND_DB_USER",     "postgres");
    private static final String PASSWORD = env("VAULTMIND_DB_PASSWORD", "Anhad@14576");
    private Connection connection;
    @Override
    public void init() throws SQLException {
        connection();
        seedAdmin();
    }
    private void seedAdmin() throws SQLException {
        if (!exists("SELECT 1 FROM users WHERE role = 'admin'")) {
            update(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                "admin",
                BCrypt.withDefaults().hashToString(12, "admin".toCharArray()),
                "admin"
            );
        }
    }

    @Override
    public int update(String sql, Object... params) throws SQLException {
        try (PreparedStatement statement = prepare(sql, params)) {
            return statement.executeUpdate();
        }
    }

    @Override
    public long insert(String sql, Object... params) throws SQLException {
        try (PreparedStatement statement = connection().prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            bind(statement, params);
            statement.executeUpdate();
            try (ResultSet keys = statement.getGeneratedKeys()) {
                if (keys.next()) return keys.getLong(1);
                throw new SQLException("Insert failed.");
            }
        }
    }

    @Override
    public boolean exists(String sql, Object... params) throws SQLException {
        return queryOne(sql, rs -> true, params) != null;
    }

    @Override
    public <T> T queryOne(String sql, DB.Mapper<T> mapper, Object... params) throws SQLException {
        try (PreparedStatement statement = prepare(sql, params);
             ResultSet resultSet = statement.executeQuery()) {
            return resultSet.next() ? mapper.map(resultSet) : null;
        }
    }

    @Override
    public <T> List<T> queryAll(String sql, DB.Mapper<T> mapper, Object... params) throws SQLException {
        try (PreparedStatement statement = prepare(sql, params);
             ResultSet resultSet = statement.executeQuery()) {
            List<T> results = new ArrayList<>();
            while (resultSet.next()) results.add(mapper.map(resultSet));
            return results;
        }
    }

    private Connection connection() throws SQLException {
        if (connection == null || connection.isClosed()) {
            connection = DriverManager.getConnection(URL, USER, PASSWORD);
        }
        return connection;
    }

    private PreparedStatement prepare(String sql, Object... params) throws SQLException {
        PreparedStatement statement = connection().prepareStatement(sql);
        bind(statement, params);
        return statement;
    }

    private void bind(PreparedStatement statement, Object... params) throws SQLException {
        for (int i = 0; i < params.length; i++) statement.setObject(i + 1, params[i]);
    }

    private static String env(String key, String fallback) {
        String value = System.getenv(key);
        return value == null || value.isBlank() ? fallback : value;
    }
}

// Deprecated static utility (Kept for compatibility during refactoring if needed, but transitioned to instance)
final class DB {
    private DB() {}
    @FunctionalInterface interface Mapper<T> { T map(ResultSet resultSet) throws SQLException; }
}

//   ABSTRACTION: Encryption Provider  
interface EncryptionProvider {
    byte[] encrypt(byte[] data) throws Exception;
    byte[] decrypt(byte[] encrypted) throws Exception;
}
//   INHERITANCE: AesGcmEncryption implements EncryptionProvider  
final class AesGcmEncryption implements EncryptionProvider {
    private static final int KEY_LENGTH = 32;
    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH_BITS = 128;
    private static final SecureRandom RANDOM = new SecureRandom();
    @Override
    public byte[] encrypt(byte[] data) throws Exception {
        byte[] iv = new byte[IV_LENGTH];
        RANDOM.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(loadKey(), "AES"), new GCMParameterSpec(TAG_LENGTH_BITS, iv));
        byte[] encrypted = cipher.doFinal(data);
        return ByteBuffer.allocate(IV_LENGTH + encrypted.length).put(iv).put(encrypted).array();
    }
    @Override
    public byte[] decrypt(byte[] encrypted) throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(encrypted);
        byte[] iv = new byte[IV_LENGTH];
        buffer.get(iv);
        byte[] cipherText = new byte[buffer.remaining()];
        buffer.get(cipherText);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(loadKey(), "AES"), new GCMParameterSpec(TAG_LENGTH_BITS, iv));
        return cipher.doFinal(cipherText);
    }
    private byte[] loadKey() {
        String raw = System.getenv("VAULTMIND_AES_KEY");
        byte[] key = (raw == null || raw.isBlank() ? "MyFixedKey1234567890123456789012" : raw).getBytes(StandardCharsets.UTF_8);
        return Arrays.copyOf(key, KEY_LENGTH);} }

final class FileUtil {
    static String readDocument(String filename, byte[] bytes) throws Exception {
        String name = filename.toLowerCase(Locale.ROOT);
        if (name.endsWith(".txt")) return new String(bytes, StandardCharsets.UTF_8);
        if (name.endsWith(".pdf")) {
            try (PDDocument document = Loader.loadPDF(bytes)) {
                return new PDFTextStripper().getText(document); }    }


        throw new ValidationException("Only PDF and TXT files are supported.");
    }
}

//   INHERITANCE: Hierarchy of Exceptions  
class BaseException extends RuntimeException {
    BaseException(String message) { super(message); }
}

class ApiException extends BaseException {
    private final int status;
    ApiException(int status, String message) {
        super(message);
        this.status = status;
    }
    int status() { return status; }
}

final class ValidationException extends ApiException {
    ValidationException(String message) { super(400, message); }
}
