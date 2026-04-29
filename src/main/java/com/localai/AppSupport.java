package com.localai;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

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

final class Auth {
    private Auth() {
    }

    static Session login(String username, String password) throws Exception {
        String cleanUsername = require(username, 3, "Username");
        String cleanPassword = require(password, 6, "Password");

        Session session = DB.queryOne(
            "SELECT id, username, password_hash, role FROM users WHERE username = ?",
            rs -> {
                BCrypt.Result result = BCrypt.verifyer().verify(cleanPassword.toCharArray(), rs.getString("password_hash"));
                if (!result.verified) {
                    throw new ApiException(401, "Invalid username or password.");
                }
                return new Session(rs.getInt("id"), rs.getString("username"), rs.getString("role"));
            },
            cleanUsername
        );

        if (session == null) {
            throw new ApiException(401, "Invalid username or password.");
        }
        return session;
    }

    static Session signup(String username, String password) throws Exception {
        String cleanUsername = require(username, 3, "Username");
        String cleanPassword = require(password, 6, "Password");
        if (DB.exists("SELECT 1 FROM users WHERE username = ?", cleanUsername)) {
            throw new ApiException(400, "Username already exists.");
        }

        String role = DB.exists("SELECT 1 FROM users WHERE role = 'admin'") ? "user" : "admin";
        long id = DB.insert(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            cleanUsername,
            BCrypt.withDefaults().hashToString(12, cleanPassword.toCharArray()),
            role
        );
        return new Session((int) id, cleanUsername, role);
    }

    static void updateAdmin(int userId, String username, String password) throws SQLException {
        String cleanUsername = require(username, 3, "Username");
        String cleanPassword = require(password, 6, "Password");
        DB.update(
            "UPDATE users SET username = ?, password_hash = ? WHERE id = ?",
            cleanUsername,
            BCrypt.withDefaults().hashToString(12, cleanPassword.toCharArray()),
            userId
        );
    }

    private static String require(String value, int minLength, String name) {
        String clean = value == null ? "" : value.trim();
        if (clean.length() < minLength) {
            throw new ApiException(400, name + " must be at least " + minLength + " characters.");
        }
        return clean;
    }

    record Session(int id, String username, String role) {
        boolean isAdmin() {
            return "admin".equalsIgnoreCase(role);
        }
    }
}

final class Sessions {
    private static final Map<String, Auth.Session> ACTIVE = new ConcurrentHashMap<>();
    private static final String COOKIE_NAME = "LOCALAI_SESSION";

    private Sessions() {
    }

    static void start(HttpServletResponse response, Auth.Session session) {
        String token = UUID.randomUUID().toString();
        ACTIVE.put(token, session);
        Cookie cookie = new Cookie(COOKIE_NAME, token);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setSecure(false); // Set to true if using HTTPS
        response.addCookie(cookie);
    }

    static void end(HttpServletRequest request, HttpServletResponse response) {
        String token = token(request);
        if (token != null) {
            ACTIVE.remove(token);
        }
        Cookie cookie = new Cookie(COOKIE_NAME, "");
        cookie.setPath("/");
        cookie.setMaxAge(0);
        cookie.setHttpOnly(true);
        response.addCookie(cookie);
    }

    static Auth.Session current(HttpServletRequest request) {
        String token = token(request);
        return token == null ? null : ACTIVE.get(token);
    }

    static Auth.Session require(HttpServletRequest request) {
        Auth.Session session = current(request);
        if (session == null) {
            throw new ApiException(401, "Not logged in.");
        }
        return session;
    }

    private static String token(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (COOKIE_NAME.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}

final class AppData {
    private AppData() {
    }

    static List<DocumentRef> documents(int userId) throws SQLException {
        return DB.queryAll(
            "SELECT id, filename FROM documents WHERE user_id = ? ORDER BY uploaded_at DESC",
            rs -> new DocumentRef(rs.getInt("id"), rs.getString("filename")),
            userId
        );
    }

    static List<ChatRow> messages(int userId) throws SQLException {
        return DB.queryAll(
            "SELECT role, message FROM chat_messages WHERE user_id = ? ORDER BY created_at ASC, id ASC",
            rs -> new ChatRow(rs.getString("role"), rs.getString("message")),
            userId
        );
    }

    static List<AdminDocument> adminDocuments() throws SQLException {
        return DB.queryAll(
            """
            SELECT u.username, d.id, d.filename, d.uploaded_at
            FROM documents d
            JOIN users u ON u.id = d.user_id
            ORDER BY d.uploaded_at DESC
            """,
            rs -> new AdminDocument(rs.getInt("id"), rs.getString("username"), rs.getString("filename"), rs.getTimestamp("uploaded_at").toString())
        );
    }

    static List<AdminUser> adminUsers() throws SQLException {
        return DB.queryAll(
            "SELECT id, username, role FROM users ORDER BY id ASC",
            rs -> new AdminUser(rs.getInt("id"), rs.getString("username"), rs.getString("role"))
        );
    }

    static JsonObject adminStats() throws SQLException {
        JsonObject stats = new JsonObject();
        stats.addProperty("totalUsers", DB.<Integer>queryOne("SELECT count(*) FROM users", rs -> rs.getInt(1)));
        stats.addProperty("totalDocuments", DB.<Integer>queryOne("SELECT count(*) FROM documents", rs -> rs.getInt(1)));
        stats.addProperty("totalMessages", DB.<Integer>queryOne("SELECT count(*) FROM chat_messages", rs -> rs.getInt(1)));
        return stats;
    }

    static void deleteDocumentGlobal(int docId) throws SQLException {
        DB.update("DELETE FROM documents WHERE id = ?", docId);
    }

    record AdminDocument(int id, String username, String filename, String uploadedAt) {}
    record AdminUser(int id, String username, String role) {}

    static void saveDocument(int userId, String filename, byte[] bytes) throws Exception {
        String content = FileUtil.readDocument(filename, bytes);
        DB.update(
            "INSERT INTO documents (user_id, filename, encrypted_content) VALUES (?, ?, ?)",
            userId,
            filename,
            Crypto.encrypt(content.getBytes(StandardCharsets.UTF_8))
        );
    }

    static String chat(int userId, String message) throws Exception {
        saveMessage(userId, "user", message);
        String reply = OllamaClient.chat(prompt(userId, message));
        saveMessage(userId, "assistant", reply);
        return reply;
    }

    private static void saveMessage(int userId, String role, String message) throws SQLException {
        DB.update(
            "INSERT INTO chat_messages (user_id, role, message) VALUES (?, ?, ?)",
            userId,
            role,
            message
        );
    }

    private static String prompt(int userId, String userMessage) throws Exception {
        List<DocumentRef> matches = matchDocuments(userId, userMessage);
        if (matches.isEmpty()) {
            return userMessage;
        }

        List<String> chunks = new ArrayList<>();
        for (DocumentRef document : matches) {
            byte[] encrypted = DB.queryOne(
                "SELECT encrypted_content FROM documents WHERE id = ? AND user_id = ?",
                rs -> rs.getBytes("encrypted_content"),
                document.id(),
                userId
            );
            if (encrypted == null) {
                continue;
            }

            String content = new String(Crypto.decrypt(encrypted), StandardCharsets.UTF_8);
            chunks.add("Document: " + document.filename() + System.lineSeparator() + trim(content, 12000));
        }

        if (chunks.isEmpty()) {
            return userMessage;
        }

        String names = matches.stream().map(DocumentRef::filename).reduce((a, b) -> a + ", " + b).orElse("");
        return """
            You are answering a question for a localhost-only app.
            Use the document excerpts when they support the answer, and say when they do not.

            Referenced documents: %s

            %s

            User question:
            %s
            """.formatted(names, String.join(System.lineSeparator() + System.lineSeparator(), chunks), userMessage);
    }

    private static List<DocumentRef> matchDocuments(int userId, String message) throws SQLException {
        String lowered = message.toLowerCase(Locale.ROOT);
        List<DocumentRef> matches = new ArrayList<>();
        for (DocumentRef document : documents(userId)) {
            String filename = document.filename().toLowerCase(Locale.ROOT);
            String basename = filename.contains(".") ? filename.substring(0, filename.lastIndexOf('.')) : filename;
            if (lowered.contains(filename) || lowered.contains(basename)) {
                matches.add(document);
            }
        }
        return matches;
    }

    private static String trim(String value, int max) {
        return value.length() <= max ? value : value.substring(0, max);
    }

    record DocumentRef(int id, String filename) {
    }

    record ChatRow(String role, String message) {
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

final class OllamaClient {
    private static final HttpClient CLIENT = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private static final String ENDPOINT = env("LOCALAI_OLLAMA_URL", "http://localhost:11434/api/generate");
    private static final String MODEL = env("LOCALAI_OLLAMA_MODEL", "mistral");

    private OllamaClient() {
    }

    static String chat(String prompt) throws Exception {
        JsonObject body = new JsonObject();
        body.addProperty("model", MODEL);
        body.addProperty("prompt", prompt);
        body.addProperty("stream", false);

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(ENDPOINT))
            .timeout(Duration.ofMinutes(2))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
            .build();

        HttpResponse<String> response = CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new ApiException(502, "Ollama returned HTTP " + response.statusCode() + ".");
        }

        JsonObject json = JsonParser.parseString(response.body()).getAsJsonObject();
        if (!json.has("response")) {
            throw new ApiException(502, "Unexpected Ollama response.");
        }
        return json.get("response").getAsString().trim();
    }

    private static String env(String key, String fallback) {
        String value = System.getenv(key);
        return value == null || value.isBlank() ? fallback : value;
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
