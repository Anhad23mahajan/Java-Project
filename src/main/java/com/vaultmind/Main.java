package com.vaultmind;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;
import java.util.List;

@SpringBootApplication
@RestController
public class Main {
    //   POLYMORPHISM: Interfaces allow different implementations  
    private final Database db = new PostgresDatabase();
    private final EncryptionProvider crypto = new AesGcmEncryption();
    private final AiClient ai = new OllamaAiClient();
    private final AuthService auth = new DatabaseAuthService(db);
    private final DataManager data = new SqlDataManager(db, crypto, ai);

    public static void main(String[] args) throws Exception {
        // We use a temporary instance to init because static context
        new PostgresDatabase().init();
        SpringApplication.run(Main.class, args);
    }

    @GetMapping("/api/state")
    public String state(HttpServletRequest request) throws Exception {
        return stateJson(Sessions.current(request)).toString();
    }

    @PostMapping("/api/login")
    public String login(@RequestBody String body, HttpServletResponse response) throws Exception {
        JsonObject json = JsonParser.parseString(body).getAsJsonObject();
        Auth.Session session = auth.login(required(json, "username"), required(json, "password"));
        Sessions.start(response, session);
        return stateJson(session).toString();
    }

    @PostMapping("/api/signup")
    public String signup(@RequestBody String body, HttpServletResponse response) throws Exception {
        JsonObject json = JsonParser.parseString(body).getAsJsonObject();
        Auth.Session session = auth.signup(required(json, "username"), required(json, "password"));
        Sessions.start(response, session);
        return stateJson(session).toString();
    }

    @PostMapping("/api/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        Sessions.end(request, response);
        return guestState().toString();
    }

    @PostMapping("/api/upload")
    public String upload(@RequestBody String body, HttpServletRequest request) throws Exception {
        Auth.Session session = Sessions.require(request);
        JsonObject json = JsonParser.parseString(body).getAsJsonObject();
        data.saveDocument(session.id(), required(json, "filename"), Base64.getDecoder().decode(required(json, "contentBase64")));
        return stateJson(session).toString();
    }

    @PostMapping("/api/delete-document")
    public String deleteDocument(@RequestBody String body, HttpServletRequest request) throws Exception {
        Auth.Session session = Sessions.require(request);
        int docId = Integer.parseInt(required(JsonParser.parseString(body).getAsJsonObject(), "id"));
        data.deleteDocument(session.id(), docId);
        return stateJson(session).toString();
    }

    @PostMapping("/api/rename-document")
    public String renameDocument(@RequestBody String body, HttpServletRequest request) throws Exception {
        Auth.Session session = Sessions.require(request);
        JsonObject json = JsonParser.parseString(body).getAsJsonObject();
        data.renameDocument(session.id(), Integer.parseInt(required(json, "id")), required(json, "filename"));
        return stateJson(session).toString();
    }

    @PostMapping("/api/chat")
    public String chat(@RequestBody String body, HttpServletRequest request) throws Exception {
        Auth.Session session = Sessions.require(request);
        String msg = required(JsonParser.parseString(body).getAsJsonObject(), "message");
        String reply = data.chat(session.id(), msg);
        JsonObject json = stateJson(session);
        json.addProperty("reply", reply);
        return json.toString();
    }

    @PostMapping("/api/password")
    public String changePassword(@RequestBody String body, HttpServletRequest request) throws Exception {
        Auth.Session session = Sessions.require(request);
        JsonObject json = JsonParser.parseString(body).getAsJsonObject();
        auth.changePassword(session.id(), required(json, "currentPassword"), required(json, "newPassword"));
        return stateJson(session).toString();
    }

    @PostMapping("/api/admin/update")
    public String adminUpdate(@RequestBody String body, HttpServletRequest request, HttpServletResponse response) throws Exception {
        Auth.Session session = Sessions.require(request);
        if (!session.isAdmin()) throw new ApiException(403, "Forbidden.");
        JsonObject json = JsonParser.parseString(body).getAsJsonObject();
        auth.updateAdmin(session.id(), required(json, "username"), required(json, "password"));
        Auth.Session newSession = new Auth.Session(session.id(), required(json, "username"), session.role());
        Sessions.start(response, newSession);
        return stateJson(newSession).toString();
    }

    @PostMapping("/api/admin/delete-document")
    public String adminDeleteDocument(@RequestBody String body, HttpServletRequest request) throws Exception {
        Auth.Session session = Sessions.require(request);
        if (!session.isAdmin()) throw new ApiException(403, "Forbidden.");
        data.deleteDocumentGlobal(Integer.parseInt(required(JsonParser.parseString(body).getAsJsonObject(), "id")));
        return stateJson(session).toString();
    }

    @PostMapping("/api/admin/delete-user")
    public String adminDeleteUser(@RequestBody String body, HttpServletRequest request) throws Exception {
        Auth.Session session = Sessions.require(request);
        if (!session.isAdmin()) throw new ApiException(403, "Forbidden.");
        auth.deleteUser(Integer.parseInt(required(JsonParser.parseString(body).getAsJsonObject(), "id")));
        return stateJson(session).toString();
    }

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<String> handleApiException(ApiException e) {
        JsonObject json = new JsonObject();
        json.addProperty("error", e.getMessage());
        return ResponseEntity.status(e.status()).body(json.toString());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleException(Exception e) {
        JsonObject json = new JsonObject();
        json.addProperty("error", e.getMessage() == null ? "Server error." : e.getMessage());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(json.toString());
    }

    private JsonObject stateJson(Auth.Session session) throws Exception {
        if (session == null) return guestState();
        JsonObject json = new JsonObject();
        json.addProperty("authenticated", true);
        json.addProperty("username", session.username());
        json.addProperty("role", session.role());
        json.add("documents", toDocuments(data.documents(session.id())));
        json.add("messages", toMessages(data.messages(session.id())));
        if (session.isAdmin()) {
            json.add("adminDocuments", toAdminDocuments(data.adminDocuments()));
            json.add("adminUsers", toAdminUsers(data.adminUsers()));
            json.add("adminStats", data.adminStats());
        }
        return json;
    }

    private JsonObject guestState() {
        JsonObject json = new JsonObject();
        json.addProperty("authenticated", false);
        return json;
    }

    private JsonArray toDocuments(List<AppData.DocumentRef> docs) {
        JsonArray arr = new JsonArray();
        for (AppData.DocumentRef d : docs) {
            JsonObject item = new JsonObject();
            item.addProperty("id", d.id());
            item.addProperty("filename", d.filename());
            arr.add(item);
        }
        return arr;
    }

    private JsonArray toMessages(List<AppData.ChatRow> msgs) {
        JsonArray arr = new JsonArray();
        for (AppData.ChatRow m : msgs) {
            JsonObject item = new JsonObject();
            item.addProperty("role", m.role());
            item.addProperty("message", m.message());
            arr.add(item);
        }
        return arr;
    }

    private JsonArray toAdminDocuments(List<AppData.AdminDocument> rows) {
        JsonArray arr = new JsonArray();
        for (AppData.AdminDocument r : rows) {
            JsonObject item = new JsonObject();
            item.addProperty("id", r.id());
            item.addProperty("username", r.username());
            item.addProperty("filename", r.filename());
            item.addProperty("uploadedAt", r.uploadedAt());
            arr.add(item);
        }
        return arr;
    }

    private JsonArray toAdminUsers(List<AppData.AdminUser> rows) {
        JsonArray arr = new JsonArray();
        for (AppData.AdminUser r : rows) {
            JsonObject item = new JsonObject();
            item.addProperty("id", r.id());
            item.addProperty("username", r.username());
            item.addProperty("role", r.role());
            arr.add(item);
        }
        return arr;
    }

    private String required(JsonObject json, String key) {
        if (!json.has(key) || json.get(key).getAsString().trim().isEmpty()) {
            throw new ValidationException(key + " is required.");
        }
        return json.get(key).getAsString().trim();
    }
}
