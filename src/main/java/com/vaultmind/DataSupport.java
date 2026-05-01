package com.vaultmind;

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

//   ABSTRACTION: DataManager Interface  
interface DataManager {
    List<AppData.DocumentRef> documents(int userId) throws SQLException;
    List<AppData.ChatRow> messages(int userId) throws SQLException;
    List<AppData.AdminDocument> adminDocuments() throws SQLException;
    List<AppData.AdminUser> adminUsers() throws SQLException;
    JsonObject adminStats() throws SQLException;
    void deleteDocument(int userId, int docId) throws SQLException;
    void deleteDocumentGlobal(int docId) throws SQLException;
    void renameDocument(int userId, int docId, String newName) throws SQLException;
    void saveDocument(int userId, String filename, byte[] bytes) throws Exception;
    String chat(int userId, String message) throws Exception;
}

//   INHERITANCE: SqlDataManager implements DataManager  
final class SqlDataManager implements DataManager {
    private final Database db;
    private final EncryptionProvider crypto;
    private final AiClient ai;

    SqlDataManager(Database db, EncryptionProvider crypto, AiClient ai) {
        this.db = db;
        this.crypto = crypto;
        this.ai = ai;
    }

    @Override
    public List<AppData.DocumentRef> documents(int userId) throws SQLException {
        return db.queryAll("SELECT id, filename FROM documents WHERE user_id = ? ORDER BY uploaded_at DESC",
            rs -> new AppData.DocumentRef(rs.getInt("id"), rs.getString("filename")), userId);
    }

    @Override
    public List<AppData.ChatRow> messages(int userId) throws SQLException {
        return db.queryAll("SELECT role, message FROM chat_messages WHERE user_id = ? ORDER BY created_at ASC",
            rs -> new AppData.ChatRow(rs.getString("role"), rs.getString("message")), userId);
    }

    @Override
    public List<AppData.AdminDocument> adminDocuments() throws SQLException {
        return db.queryAll("SELECT u.username, d.id, d.filename, d.uploaded_at FROM documents d JOIN users u ON u.id = d.user_id",
            rs -> new AppData.AdminDocument(rs.getInt("id"), rs.getString("username"), rs.getString("filename"), rs.getTimestamp("uploaded_at").toString()));
    }

    @Override
    public List<AppData.AdminUser> adminUsers() throws SQLException {
        return db.queryAll("SELECT id, username, role FROM users", rs -> new AppData.AdminUser(rs.getInt("id"), rs.getString("username"), rs.getString("role")));
    }

    @Override
    public JsonObject adminStats() throws SQLException {
        JsonObject s = new JsonObject();
        s.addProperty("totalUsers", (Number) db.queryOne("SELECT count(*) FROM users", rs -> rs.getInt(1)));
        s.addProperty("totalDocuments", (Number) db.queryOne("SELECT count(*) FROM documents", rs -> rs.getInt(1)));
        return s;
    }

    @Override
    public void deleteDocument(int userId, int docId) throws SQLException {
        if (db.update("DELETE FROM documents WHERE id = ? AND user_id = ?", docId, userId) == 0) throw new ApiException(404, "Not found.");
    }

    @Override
    public void deleteDocumentGlobal(int docId) throws SQLException {
        db.update("DELETE FROM documents WHERE id = ?", docId);
    }

    @Override
    public void renameDocument(int userId, int docId, String newName) throws SQLException {
        if (db.update("UPDATE documents SET filename = ? WHERE id = ? AND user_id = ?", newName, docId, userId) == 0) throw new ApiException(404, "Not found.");
    }

    @Override
    public void saveDocument(int userId, String filename, byte[] bytes) throws Exception {
        String content = FileUtil.readDocument(filename, bytes);
        db.update("INSERT INTO documents (user_id, filename, encrypted_content) VALUES (?, ?, ?)",
            userId, filename, crypto.encrypt(content.getBytes(StandardCharsets.UTF_8)));
    }

    @Override
    public String chat(int userId, String message) throws Exception {
        saveMessage(userId, "user", message);
        String reply = ai.generate(prompt(userId, message));
        saveMessage(userId, "assistant", reply);
        return reply;
    }

    private void saveMessage(int userId, String role, String msg) throws SQLException {
        db.update("INSERT INTO chat_messages (user_id, role, message) VALUES (?, ?, ?)", userId, role, msg);
    }

    private String prompt(int userId, String msg) throws Exception {
        List<AppData.DocumentRef> docs = match(userId, msg);
        if (docs.isEmpty()) return msg;
        StringBuilder sb = new StringBuilder("Context:\n");
        for (AppData.DocumentRef d : docs) {
            byte[] enc = db.queryOne("SELECT encrypted_content FROM documents WHERE id = ?", rs -> rs.getBytes(1), d.id());
            if (enc != null) sb.append("Doc ").append(d.filename()).append(": ").append(new String(crypto.decrypt(enc), StandardCharsets.UTF_8)).append("\n");
        }
        return sb.append("\nUser: ").append(msg).toString();
    }

    private List<AppData.DocumentRef> match(int userId, String msg) throws SQLException {
        String low = msg.toLowerCase(Locale.ROOT);
        List<AppData.DocumentRef> matches = new ArrayList<>();
        for (AppData.DocumentRef d : documents(userId)) if (low.contains(d.filename().toLowerCase(Locale.ROOT))) matches.add(d);
        return matches;
    }
}

//   ABSTRACTION: AiClient Interface  
interface AiClient {
    String generate(String prompt) throws Exception;
}

//   INHERITANCE: OllamaAiClient implements AiClient  
final class OllamaAiClient implements AiClient {
    private static final HttpClient CLIENT = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private static final String URL = "http://localhost:11434/api/generate";

    @Override
    public String generate(String prompt) throws Exception {
        JsonObject b = new JsonObject();
        b.addProperty("model", "tinyllama");
        b.addProperty("prompt", prompt);
        b.addProperty("stream", false);
        HttpRequest req = HttpRequest.newBuilder().uri(URI.create(URL)).POST(HttpRequest.BodyPublishers.ofString(b.toString())).build();
        HttpResponse<String> res = CLIENT.send(req, HttpResponse.BodyHandlers.ofString());
        if (res.statusCode() != 200) throw new ApiException(502, "AI error.");
        return JsonParser.parseString(res.body()).getAsJsonObject().get("response").getAsString().trim();
    }
}

final class AppData {
    private AppData() {}
    record DocumentRef(int id, String filename) {}
    record ChatRow(String role, String message) {}
    record AdminDocument(int id, String username, String filename, String uploadedAt) {}
    record AdminUser(int id, String username, String role) {}
}
