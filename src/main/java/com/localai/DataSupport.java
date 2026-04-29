package com.localai;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

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
            rs -> new AdminDocument(
                rs.getInt("id"),
                rs.getString("username"),
                rs.getString("filename"),
                rs.getTimestamp("uploaded_at").toString()
            )
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

    record AdminDocument(int id, String username, String filename, String uploadedAt) {
    }

    record AdminUser(int id, String username, String role) {
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
