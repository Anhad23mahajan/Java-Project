package com.localai;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.Executors;

public class Main {
    private static final int PORT = Integer.parseInt(env("LOCALAI_PORT", "8080"));
    private static final byte[] INDEX_HTML = readResource("/index.html");

    public static void main(String[] args) throws Exception {
        DB.init();

        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), PORT), 0);
        server.setExecutor(Executors.newCachedThreadPool());

        server.createContext("/", exchange -> {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod()) || !"/".equals(exchange.getRequestURI().getPath())) {
                sendJson(exchange, 404, error("Not found."));
                return;
            }
            send(exchange, 200, "text/html; charset=utf-8", INDEX_HTML);
        });

        server.createContext("/api/state", exchange -> handle(exchange, "GET", () -> stateJson(Sessions.current(exchange))));
        server.createContext("/api/login", exchange -> handle(exchange, "POST", () -> {
            JsonObject body = readJson(exchange);
            Auth.Session session = Auth.login(required(body, "username"), required(body, "password"));
            Sessions.start(exchange, session);
            return stateJson(session);
        }));
        server.createContext("/api/signup", exchange -> handle(exchange, "POST", () -> {
            JsonObject body = readJson(exchange);
            Auth.Session session = Auth.signup(required(body, "username"), required(body, "password"));
            Sessions.start(exchange, session);
            return stateJson(session);
        }));
        server.createContext("/api/logout", exchange -> handle(exchange, "POST", () -> {
            Sessions.end(exchange);
            return guestState();
        }));
        server.createContext("/api/upload", exchange -> handle(exchange, "POST", () -> {
            Auth.Session session = Sessions.require(exchange);
            JsonObject body = readJson(exchange);
            AppData.saveDocument(session.id(), required(body, "filename"), Base64.getDecoder().decode(required(body, "contentBase64")));
            return stateJson(session);
        }));
        server.createContext("/api/chat", exchange -> handle(exchange, "POST", () -> {
            Auth.Session session = Sessions.require(exchange);
            JsonObject body = readJson(exchange);
            String message = required(body, "message");
            String reply = AppData.chat(session.id(), message);

            JsonObject json = stateJson(session);
            json.addProperty("reply", reply);
            return json;
        }));

        server.start();
        System.out.println("Local AI web app running at http://127.0.0.1:" + PORT);
    }

    private static void handle(HttpExchange exchange, String method, ApiCall action) throws IOException {
        try {
            if (!method.equalsIgnoreCase(exchange.getRequestMethod())) {
                throw new ApiException(405, "Method not allowed.");
            }
            sendJson(exchange, 200, action.run());
        } catch (ApiException e) {
            sendJson(exchange, e.status(), error(e.getMessage()));
        } catch (Exception e) {
            sendJson(exchange, 500, error(e.getMessage() == null ? "Server error." : e.getMessage()));
        }
    }

    private static JsonObject stateJson(Auth.Session session) throws Exception {
        if (session == null) {
            return guestState();
        }

        JsonObject json = new JsonObject();
        json.addProperty("authenticated", true);
        json.addProperty("username", session.username());
        json.addProperty("role", session.role());
        json.add("documents", toDocuments(AppData.documents(session.id())));
        json.add("messages", toMessages(AppData.messages(session.id())));
        json.add("adminDocuments", session.isAdmin() ? toAdminDocuments(AppData.adminDocuments()) : new JsonArray());
        return json;
    }

    private static JsonObject guestState() {
        JsonObject json = new JsonObject();
        json.addProperty("authenticated", false);
        json.add("documents", new JsonArray());
        json.add("messages", new JsonArray());
        json.add("adminDocuments", new JsonArray());
        return json;
    }

    private static JsonArray toDocuments(List<AppData.DocumentRef> documents) {
        JsonArray array = new JsonArray();
        for (AppData.DocumentRef document : documents) {
            JsonObject item = new JsonObject();
            item.addProperty("id", document.id());
            item.addProperty("filename", document.filename());
            array.add(item);
        }
        return array;
    }

    private static JsonArray toMessages(List<AppData.ChatRow> messages) {
        JsonArray array = new JsonArray();
        for (AppData.ChatRow message : messages) {
            JsonObject item = new JsonObject();
            item.addProperty("role", message.role());
            item.addProperty("message", message.message());
            array.add(item);
        }
        return array;
    }

    private static JsonArray toAdminDocuments(List<String> rows) {
        JsonArray array = new JsonArray();
        rows.forEach(array::add);
        return array;
    }

    private static JsonObject readJson(HttpExchange exchange) throws IOException {
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        return body.isBlank() ? new JsonObject() : JsonParser.parseString(body).getAsJsonObject();
    }

    private static String required(JsonObject json, String key) {
        if (!json.has(key) || json.get(key).getAsString().trim().isEmpty()) {
            throw new ApiException(400, key + " is required.");
        }
        return json.get(key).getAsString().trim();
    }

    private static JsonObject error(String message) {
        JsonObject json = new JsonObject();
        json.addProperty("error", message);
        return json;
    }

    private static void sendJson(HttpExchange exchange, int status, JsonObject json) throws IOException {
        send(exchange, status, "application/json; charset=utf-8", json.toString().getBytes(StandardCharsets.UTF_8));
    }

    private static void send(HttpExchange exchange, int status, String contentType, byte[] body) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.sendResponseHeaders(status, body.length);
        exchange.getResponseBody().write(body);
        exchange.close();
    }

    private static byte[] readResource(String path) {
        try (InputStream stream = Main.class.getResourceAsStream(path)) {
            if (stream == null) {
                throw new IllegalStateException("Missing resource: " + path);
            }
            return stream.readAllBytes();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read resource: " + path, e);
        }
    }

    private static String env(String key, String fallback) {
        String value = System.getenv(key);
        return value == null || value.isBlank() ? fallback : value;
    }

    @FunctionalInterface
    private interface ApiCall {
        JsonObject run() throws Exception;
    }
}
