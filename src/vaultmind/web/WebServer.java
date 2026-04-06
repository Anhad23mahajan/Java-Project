package vaultmind.web;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import vaultmind.model.User;
import vaultmind.model.VaultFile;
import vaultmind.service.DatabaseManager;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;

public class WebServer {
    private final HttpServer server;
    private final SessionManager sessionManager = new SessionManager();

    public WebServer(String host, int port) throws IOException {
        InetSocketAddress address = new InetSocketAddress(InetAddress.getByName(host), port);
        this.server = HttpServer.create(address, 0);
        this.server.setExecutor(Executors.newCachedThreadPool());
        registerRoutes();
    }

    public void start() {
        server.start();
    }

    private void registerRoutes() {
        server.createContext("/", exchange -> {
            SessionManager.Session session = getAuthenticatedSession(exchange);
            if (session == null) {
                redirect(exchange, "/login");
            } else {
                redirect(exchange, "/dashboard");
            }
        });

        server.createContext("/login", wrap(this::handleLogin));
        server.createContext("/register", wrap(this::handleRegister));
        server.createContext("/dashboard", wrap(this::handleDashboard));
        server.createContext("/files", wrap(this::handleFileCreate));
        server.createContext("/logout", wrap(this::handleLogout));
        server.createContext("/favicon.ico", exchange -> sendResponse(exchange, 204, "", "text/plain; charset=UTF-8"));
    }

    private HttpHandler wrap(RouteHandler handler) {
        return exchange -> {
            try {
                handler.handle(exchange);
            } catch (SQLException e) {
                sendResponse(exchange, 500, HtmlRenderer.renderErrorPage("Database Error", e.getMessage()), "text/html; charset=UTF-8");
            } catch (Exception e) {
                sendResponse(exchange, 500, HtmlRenderer.renderErrorPage("Server Error", e.getMessage()), "text/html; charset=UTF-8");
            }
        };
    }

    private void handleLogin(HttpExchange exchange) throws IOException, SQLException {
        if ("GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            if (getAuthenticatedSession(exchange) != null) {
                redirect(exchange, "/dashboard");
                return;
            }

            sendResponse(exchange, 200, HtmlRenderer.renderLoginPage(null, false), "text/html; charset=UTF-8");
            return;
        }

        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            methodNotAllowed(exchange);
            return;
        }

        Map<String, String> formData = readFormData(exchange);
        String username = trimmed(formData.get("username"));
        String password = trimmed(formData.get("password"));

        if (username.isBlank() || password.isBlank()) {
            sendResponse(exchange, 400, HtmlRenderer.renderLoginPage("Username and password are required.", false), "text/html; charset=UTF-8");
            return;
        }

        User user = DatabaseManager.getUserByUsername(username);
        String hashedPassword = DatabaseManager.hashPassword(password);

        if (user == null || hashedPassword == null || !hashedPassword.equals(user.getPasswordHash())) {
            sendResponse(exchange, 401, HtmlRenderer.renderLoginPage("Invalid username or password.", false), "text/html; charset=UTF-8");
            return;
        }

        SessionManager.Session session = sessionManager.createSession(user);
        exchange.getResponseHeaders().add("Set-Cookie", buildSessionCookie(session.getToken()));
        redirect(exchange, "/dashboard");
    }

    private void handleRegister(HttpExchange exchange) throws IOException, SQLException {
        if ("GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendResponse(exchange, 200, HtmlRenderer.renderRegisterPage(null), "text/html; charset=UTF-8");
            return;
        }

        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            methodNotAllowed(exchange);
            return;
        }

        Map<String, String> formData = readFormData(exchange);
        String username = trimmed(formData.get("username"));
        String password = trimmed(formData.get("password"));

        if (username.length() < 3) {
            sendResponse(exchange, 400, HtmlRenderer.renderRegisterPage("Username must be at least 3 characters."), "text/html; charset=UTF-8");
            return;
        }

        if (password.length() < 6) {
            sendResponse(exchange, 400, HtmlRenderer.renderRegisterPage("Password must be at least 6 characters."), "text/html; charset=UTF-8");
            return;
        }

        try {
            DatabaseManager.addUser(username, DatabaseManager.hashPassword(password), "user");
            sendResponse(exchange, 201, HtmlRenderer.renderLoginPage("Account created. You can log in now.", true), "text/html; charset=UTF-8");
        } catch (SQLException e) {
            String message = "23505".equals(e.getSQLState())
                    ? "That username already exists."
                    : "Registration failed: " + e.getMessage();
            sendResponse(exchange, 400, HtmlRenderer.renderRegisterPage(message), "text/html; charset=UTF-8");
        }
    }

    private void handleDashboard(HttpExchange exchange) throws IOException, SQLException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            methodNotAllowed(exchange);
            return;
        }

        SessionManager.Session session = requireSession(exchange);
        if (session == null) {
            return;
        }

        if ("admin".equalsIgnoreCase(session.getRole())) {
            List<User> users = DatabaseManager.getAllUsers();
            List<VaultFile> files = DatabaseManager.getAllFiles();
            sendResponse(exchange, 200, HtmlRenderer.renderAdminDashboard(session, users, files), "text/html; charset=UTF-8");
            return;
        }

        List<VaultFile> files = DatabaseManager.getFilesByUser(session.getUserId());
        sendResponse(exchange, 200, HtmlRenderer.renderUserDashboard(session, files, null, false), "text/html; charset=UTF-8");
    }

    private void handleFileCreate(HttpExchange exchange) throws IOException, SQLException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            methodNotAllowed(exchange);
            return;
        }

        SessionManager.Session session = requireSession(exchange);
        if (session == null) {
            return;
        }

        if ("admin".equalsIgnoreCase(session.getRole())) {
            sendResponse(exchange, 403, HtmlRenderer.renderErrorPage("Forbidden", "Admins do not create personal vault records from this form."), "text/html; charset=UTF-8");
            return;
        }

        Map<String, String> formData = readFormData(exchange);
        String fileName = trimmed(formData.get("fileName"));
        String encryptedPath = trimmed(formData.get("encryptedPath"));

        if (fileName.isBlank() || encryptedPath.isBlank()) {
            List<VaultFile> files = DatabaseManager.getFilesByUser(session.getUserId());
            sendResponse(exchange, 400, HtmlRenderer.renderUserDashboard(session, files, "Both fields are required.", false), "text/html; charset=UTF-8");
            return;
        }

        DatabaseManager.addFile(session.getUserId(), fileName, encryptedPath);
        List<VaultFile> files = DatabaseManager.getFilesByUser(session.getUserId());
        sendResponse(exchange, 200, HtmlRenderer.renderUserDashboard(session, files, "Vault record saved.", true), "text/html; charset=UTF-8");
    }

    private void handleLogout(HttpExchange exchange) throws IOException {
        String token = getSessionToken(exchange);
        sessionManager.removeSession(token);
        Headers headers = exchange.getResponseHeaders();
        headers.add("Set-Cookie", "VAULTMIND_SESSION=deleted; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");
        redirect(exchange, "/login");
    }

    private SessionManager.Session requireSession(HttpExchange exchange) throws IOException {
        SessionManager.Session session = getAuthenticatedSession(exchange);
        if (session == null) {
            redirect(exchange, "/login");
        }
        return session;
    }

    private SessionManager.Session getAuthenticatedSession(HttpExchange exchange) {
        return sessionManager.getSession(getSessionToken(exchange));
    }

    private String getSessionToken(HttpExchange exchange) {
        String cookieHeader = exchange.getRequestHeaders().getFirst("Cookie");
        if (cookieHeader == null || cookieHeader.isBlank()) {
            return null;
        }

        String[] cookies = cookieHeader.split(";");
        for (String cookie : cookies) {
            String[] parts = cookie.trim().split("=", 2);
            if (parts.length == 2 && "VAULTMIND_SESSION".equals(parts[0])) {
                return parts[1];
            }
        }
        return null;
    }

    private String buildSessionCookie(String token) {
        return "VAULTMIND_SESSION=" + token + "; Path=/; HttpOnly; SameSite=Lax";
    }

    private Map<String, String> readFormData(HttpExchange exchange) throws IOException {
        String body = readBody(exchange.getRequestBody());
        return parseUrlEncoded(body);
    }

    private String readBody(InputStream inputStream) throws IOException {
        return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
    }

    private Map<String, String> parseUrlEncoded(String raw) throws IOException {
        if (raw == null || raw.isBlank()) {
            return Collections.emptyMap();
        }

        Map<String, String> values = new HashMap<>();
        String[] pairs = raw.split("&");
        for (String pair : pairs) {
            String[] parts = pair.split("=", 2);
            String key = URLDecoder.decode(parts[0], StandardCharsets.UTF_8);
            String value = parts.length > 1 ? URLDecoder.decode(parts[1], StandardCharsets.UTF_8) : "";
            values.put(key, value);
        }
        return values;
    }

    private String trimmed(String value) {
        return value == null ? "" : value.trim();
    }

    private void redirect(HttpExchange exchange, String location) throws IOException {
        exchange.getResponseHeaders().set("Location", location);
        exchange.sendResponseHeaders(302, -1);
        exchange.close();
    }

    private void methodNotAllowed(HttpExchange exchange) throws IOException {
        sendResponse(exchange, 405, HtmlRenderer.renderErrorPage("Method Not Allowed", "The requested HTTP method is not supported for this route."), "text/html; charset=UTF-8");
    }

    private void sendResponse(HttpExchange exchange, int statusCode, String body, String contentType) throws IOException {
        byte[] responseBytes = body.getBytes(StandardCharsets.UTF_8);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", contentType);
        headers.set("Cache-Control", "no-store");
        exchange.sendResponseHeaders(statusCode, responseBytes.length);
        try (OutputStream outputStream = exchange.getResponseBody()) {
            outputStream.write(responseBytes);
        }
    }

    @FunctionalInterface
    private interface RouteHandler {
        void handle(HttpExchange exchange) throws Exception;
    }
}
