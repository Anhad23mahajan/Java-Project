package com.localai;

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
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

final class DB {
    private static final String URL = env("LOCALAI_DB_URL", "jdbc:postgresql://localhost:5432/localai");
    private static final String USER = env("LOCALAI_DB_USER", "postgres");
    private static final String PASSWORD = env("LOCALAI_DB_PASSWORD", "password");
    private static Connection connection;

    private DB() {
    }

    static void init() throws SQLException {
        connection();
        seedAdmin();
    }

    private static void seedAdmin() throws SQLException {
        if (!exists("SELECT 1 FROM users WHERE role = 'admin'")) {
            update(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                "admin",
                BCrypt.withDefaults().hashToString(12, "admin".toCharArray()),
                "admin"
            );
        }
    }

    static int update(String sql, Object... params) throws SQLException {
        try (PreparedStatement statement = prepare(sql, params)) {
            return statement.executeUpdate();
        }
    }

    static long insert(String sql, Object... params) throws SQLException {
        try (PreparedStatement statement = connection().prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            bind(statement, params);
            statement.executeUpdate();
            try (ResultSet keys = statement.getGeneratedKeys()) {
                if (keys.next()) {
                    return keys.getLong(1);
                }
                throw new SQLException("Insert succeeded but no generated key was returned.");
            }
        }
    }

    static boolean exists(String sql, Object... params) throws SQLException {
        return queryOne(sql, rs -> true, params) != null;
    }

    static <T> T queryOne(String sql, Mapper<T> mapper, Object... params) throws SQLException {
        try (PreparedStatement statement = prepare(sql, params);
             ResultSet resultSet = statement.executeQuery()) {
            return resultSet.next() ? mapper.map(resultSet) : null;
        }
    }

    static <T> List<T> queryAll(String sql, Mapper<T> mapper, Object... params) throws SQLException {
        try (PreparedStatement statement = prepare(sql, params);
             ResultSet resultSet = statement.executeQuery()) {
            List<T> results = new ArrayList<>();
            while (resultSet.next()) {
                results.add(mapper.map(resultSet));
            }
            return results;
        }
    }

    private static Connection connection() throws SQLException {
        if (connection == null || connection.isClosed()) {
            connection = DriverManager.getConnection(URL, USER, PASSWORD);
        }
        return connection;
    }

    private static PreparedStatement prepare(String sql, Object... params) throws SQLException {
        PreparedStatement statement = connection().prepareStatement(sql);
        bind(statement, params);
        return statement;
    }

    private static void bind(PreparedStatement statement, Object... params) throws SQLException {
        for (int i = 0; i < params.length; i++) {
            statement.setObject(i + 1, params[i]);
        }
    }

    private static String env(String key, String fallback) {
        String value = System.getenv(key);
        return value == null || value.isBlank() ? fallback : value;
    }

    @FunctionalInterface
    interface Mapper<T> {
        T map(ResultSet resultSet) throws SQLException;
    }
}

final class Crypto {
    private static final int KEY_LENGTH = 32;
    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH_BITS = 128;
    private static final String DEFAULT_KEY = "MyFixedKey1234567890123456789012";
    private static final SecureRandom RANDOM = new SecureRandom();

    private Crypto() {
    }

    static byte[] encrypt(byte[] data) throws Exception {
        byte[] iv = new byte[IV_LENGTH];
        RANDOM.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(loadKey(), "AES"), new GCMParameterSpec(TAG_LENGTH_BITS, iv));
        byte[] encrypted = cipher.doFinal(data);
        return ByteBuffer.allocate(IV_LENGTH + encrypted.length).put(iv).put(encrypted).array();
    }

    static byte[] decrypt(byte[] encrypted) throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(encrypted);
        byte[] iv = new byte[IV_LENGTH];
        buffer.get(iv);
        byte[] cipherText = new byte[buffer.remaining()];
        buffer.get(cipherText);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(loadKey(), "AES"), new GCMParameterSpec(TAG_LENGTH_BITS, iv));
        return cipher.doFinal(cipherText);
    }

    private static byte[] loadKey() {
        String raw = System.getenv("LOCALAI_AES_KEY");
        byte[] key = (raw == null || raw.isBlank() ? DEFAULT_KEY : raw).getBytes(StandardCharsets.UTF_8);
        return Arrays.copyOf(key, KEY_LENGTH);
    }
}

final class FileUtil {
    private FileUtil() {
    }

    static String readDocument(String filename, byte[] bytes) throws Exception {
        String name = filename.toLowerCase(Locale.ROOT);
        if (name.endsWith(".txt")) {
            return new String(bytes, StandardCharsets.UTF_8);
        }
        if (name.endsWith(".pdf")) {
            try (PDDocument document = Loader.loadPDF(bytes)) {
                return new PDFTextStripper().getText(document);
            }
        }
        throw new ApiException(400, "Only PDF and TXT files are supported.");
    }
}

final class ApiException extends RuntimeException {
    private final int status;

    ApiException(int status, String message) {
        super(message);
        this.status = status;
    }

    int status() {
        return status;
    }
}
