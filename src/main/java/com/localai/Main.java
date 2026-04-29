package com.localai;

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

    public static void main(String[] args) throws Exception {
        DB.init();
        SpringApplication.run(Main.class, args);
    }

    @GetMapping("/api/state")
    public String state(HttpServletRequest request) throws Exception {
        return stateJson(Sessions.current(request)).toString();
    }

    @PostMapping("/api/login")
    public String login(@RequestBody String body, HttpServletResponse response) throws Exception {
        JsonObject json = JsonParser.parseString(body).getAsJsonObject();
        Auth.Session session = Auth.login(required(json, "username"), required(json, "password"));
        Sessions.start(response, session);
        return stateJson(session).toString();
    }

    @PostMapping("/api/signup")
    public String signup(@RequestBody String body, HttpServletResponse response) throws Exception {
        JsonObject json = JsonParser.parseString(body).getAsJsonObject();
        Auth.Session session = Auth.signup(required(json, "username"), required(json, "password"));
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
        AppData.saveDocument(session.id(), required(json, "filename"), Base64.getDecoder().decode(required(json, "contentBase64")));
        return stateJson(session).toString();
    }

    @PostMapping("/api/chat")
    public String chat(@RequestBody String body, HttpServletRequest request) throws Exception {
        Auth.Session session = Sessions.require(request);
        JsonObject jsonBody = JsonParser.parseString(body).getAsJsonObject();
        String message = required(jsonBody, "message");
        String reply = AppData.chat(session.id(), message);

        JsonObject json = stateJson(session);
        json.addProperty("reply", reply);
        return json.toString();
    }

    @PostMapping("/api/password")
    public String changePassword(@RequestBody String body, HttpServletRequest request) throws Exception {
        Auth.Session session = Sessions.require(request);
        JsonObject jsonBody = JsonParser.parseString(body).getAsJsonObject();
        Auth.changePassword(
            session.id(),
            required(jsonBody, "currentPassword"),
            required(jsonBody, "newPassword")
        );
        return stateJson(session).toString();
    }

    @PostMapping("/api/admin/update")
    public String adminUpdate(@RequestBody String body, HttpServletRequest request, HttpServletResponse response) throws Exception {
        Auth.Session session = Sessions.require(request);
        if (!session.isAdmin()) {
            throw new ApiException(403, "Forbidden.");
        }
        JsonObject jsonBody = JsonParser.parseString(body).getAsJsonObject();
        Auth.updateAdmin(session.id(), required(jsonBody, "username"), required(jsonBody, "password"));
        
        Auth.Session newSession = new Auth.Session(session.id(), required(jsonBody, "username"), session.role());
        Sessions.start(response, newSession);
        return stateJson(newSession).toString();
    }

    @PostMapping("/api/admin/delete-document")
    public String adminDeleteDocument(@RequestBody String body, HttpServletRequest request) throws Exception {
        Auth.Session session = Sessions.require(request);
        if (!session.isAdmin()) {
            throw new ApiException(403, "Forbidden.");
        }
        JsonObject jsonBody = JsonParser.parseString(body).getAsJsonObject();
        int docId = Integer.parseInt(required(jsonBody, "id"));
        AppData.deleteDocumentGlobal(docId);
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
        if (session == null) {
            return guestState();
        }

        JsonObject json = new JsonObject();
        json.addProperty("authenticated", true);
        json.addProperty("username", session.username());
        json.addProperty("role", session.role());
        json.add("documents", toDocuments(AppData.documents(session.id())));
        json.add("messages", toMessages(AppData.messages(session.id())));
        
        if (session.isAdmin()) {
            json.add("adminDocuments", toAdminDocuments(AppData.adminDocuments()));
            json.add("adminUsers", toAdminUsers(AppData.adminUsers()));
            json.add("adminStats", AppData.adminStats());
        } else {
            json.add("adminDocuments", new JsonArray());
            json.add("adminUsers", new JsonArray());
            json.add("adminStats", new JsonObject());
        }
        return json;
    }

    private JsonObject guestState() {
        JsonObject json = new JsonObject();
        json.addProperty("authenticated", false);
        json.add("documents", new JsonArray());
        json.add("messages", new JsonArray());
        json.add("adminDocuments", new JsonArray());
        json.add("adminUsers", new JsonArray());
        json.add("adminStats", new JsonObject());
        return json;
    }

    private JsonArray toDocuments(List<AppData.DocumentRef> documents) {
        JsonArray array = new JsonArray();
        for (AppData.DocumentRef document : documents) {
            JsonObject item = new JsonObject();
            item.addProperty("id", document.id());
            item.addProperty("filename", document.filename());
            array.add(item);
        }
        return array;
    }

    private JsonArray toMessages(List<AppData.ChatRow> messages) {
        JsonArray array = new JsonArray();
        for (AppData.ChatRow message : messages) {
            JsonObject item = new JsonObject();
            item.addProperty("role", message.role());
            item.addProperty("message", message.message());
            array.add(item);
        }
        return array;
    }

    private JsonArray toAdminDocuments(List<AppData.AdminDocument> rows) {
        JsonArray array = new JsonArray();
        for (AppData.AdminDocument row : rows) {
            JsonObject item = new JsonObject();
            item.addProperty("id", row.id());
            item.addProperty("username", row.username());
            item.addProperty("filename", row.filename());
            item.addProperty("uploadedAt", row.uploadedAt());
            array.add(item);
        }
        return array;
    }

    private JsonArray toAdminUsers(List<AppData.AdminUser> rows) {
        JsonArray array = new JsonArray();
        for (AppData.AdminUser row : rows) {
            JsonObject item = new JsonObject();
            item.addProperty("id", row.id());
            item.addProperty("username", row.username());
            item.addProperty("role", row.role());
            array.add(item);
        }
        return array;
    }

    private String required(JsonObject json, String key) {
        if (!json.has(key) || json.get(key).getAsString().trim().isEmpty()) {
            throw new ApiException(400, key + " is required.");
        }
        return json.get(key).getAsString().trim();
    }
}
