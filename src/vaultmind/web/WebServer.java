package vaultmind.web;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import vaultmind.model.User;
import vaultmind.model.VaultFile;
import vaultmind.service.DatabaseManager;
import vaultmind.service.EncryptionService;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URLConnection;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Main Web Server and Route Handler
 */
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
        server.createContext("/files/view", wrap(this::handleFileView));
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
            String message = "23505".equals(e.getSQLState()) ? "That username already exists." : "Registration failed: " + e.getMessage();
            sendResponse(exchange, 400, HtmlRenderer.renderRegisterPage(message), "text/html; charset=UTF-8");
        }
    }

    private void handleDashboard(HttpExchange exchange) throws IOException, SQLException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            methodNotAllowed(exchange);
            return;
        }

        SessionManager.Session session = requireSession(exchange);
        if (session == null) return;

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
        if (session == null) return;

        if ("admin".equalsIgnoreCase(session.getRole())) {
            sendResponse(exchange, 403, HtmlRenderer.renderErrorPage("Forbidden", "Admins do not create personal vault records."), "text/html; charset=UTF-8");
            return;
        }

        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (contentType == null || !contentType.startsWith("multipart/form-data")) {
            sendResponse(exchange, 400, HtmlRenderer.renderErrorPage("Bad Request", "Expected multipart/form-data"), "text/html; charset=UTF-8");
            return;
        }

        try {
            byte[] body = exchange.getRequestBody().readAllBytes();
            String boundary = contentType.split("boundary=")[1];
            String bodyStr = new String(body, StandardCharsets.ISO_8859_1);
            int fileStart = bodyStr.indexOf("\r\n\r\n") + 4;
            int fileEnd = bodyStr.lastIndexOf("\r\n--" + boundary);
            
            if (fileStart < 4 || fileEnd <= fileStart) throw new Exception("Could not parse file.");

            String fileName = "uploaded_file";
            int nameIndex = bodyStr.indexOf("filename=\"");
            if (nameIndex != -1) {
                int nameEnd = bodyStr.indexOf("\"", nameIndex + 10);
                fileName = bodyStr.substring(nameIndex + 10, nameEnd);
            }

            byte[] fileContent = new byte[fileEnd - fileStart];
            System.arraycopy(body, fileStart, fileContent, 0, fileContent.length);

            byte[] encrypted = vaultmind.service.EncryptionService.encrypt(fileContent, session.getUsername() + "vault-secret");
            DatabaseManager.addFile(session.getUserId(), fileName, "Stored in Database", encrypted);
            
            List<VaultFile> files = DatabaseManager.getFilesByUser(session.getUserId());
            sendResponse(exchange, 200, HtmlRenderer.renderUserDashboard(session, files, "File encrypted and saved.", true), "text/html; charset=UTF-8");
        } catch (Exception e) {
            sendResponse(exchange, 500, HtmlRenderer.renderErrorPage("Upload Error", e.getMessage()), "text/html; charset=UTF-8");
        }
    }

    private void handleFileView(HttpExchange exchange) throws IOException, SQLException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            methodNotAllowed(exchange);
            return;
        }

        SessionManager.Session session = requireSession(exchange);
        if (session == null) return;

        if ("admin".equalsIgnoreCase(session.getRole())) {
            sendResponse(exchange, 403, HtmlRenderer.renderErrorPage("Forbidden", "Admins cannot open decrypted user files."), "text/html; charset=UTF-8");
            return;
        }

        Integer fileId = parsePositiveInt(readQueryParams(exchange).get("id"));
        if (fileId == null) {
            sendResponse(exchange, 400, HtmlRenderer.renderErrorPage("Bad Request", "A valid file id is required."), "text/html; charset=UTF-8");
            return;
        }

        VaultFile file = DatabaseManager.getFileByIdForUser(fileId, session.getUserId());
        if (file == null || file.getFileContent() == null) {
            sendResponse(exchange, 404, HtmlRenderer.renderErrorPage("Not Found", "Encrypted file record was not found."), "text/html; charset=UTF-8");
            return;
        }

        byte[] responseBytes = null;
        try {
            SessionManager.DecryptedFile decryptedFile = sessionManager.getOrCreateDecryptedFile(
                    session,
                    file,
                    session.getUsername() + "vault-secret"
            );
            responseBytes = Arrays.copyOf(decryptedFile.getContent(), decryptedFile.getContent().length);
            sendFileResponse(exchange, 200, responseBytes, decryptedFile.getContentType(), decryptedFile.getFileName());
        } catch (Exception e) {
            sendResponse(exchange, 500, HtmlRenderer.renderErrorPage("Decryption Error", e.getMessage()), "text/html; charset=UTF-8");
        } finally {
            if (responseBytes != null) {
                Arrays.fill(responseBytes, (byte) 0);
            }
        }
    }

    private void handleLogout(HttpExchange exchange) throws IOException {
        String token = getSessionToken(exchange);
        sessionManager.removeSession(token);
        exchange.getResponseHeaders().add("Set-Cookie", "VAULTMIND_SESSION=deleted; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");
        redirect(exchange, "/login");
    }

    private SessionManager.Session requireSession(HttpExchange exchange) throws IOException {
        SessionManager.Session session = getAuthenticatedSession(exchange);
        if (session == null) redirect(exchange, "/login");
        return session;
    }

    private SessionManager.Session getAuthenticatedSession(HttpExchange exchange) {
        return sessionManager.getSession(getSessionToken(exchange));
    }

    private String getSessionToken(HttpExchange exchange) {
        String cookieHeader = exchange.getRequestHeaders().getFirst("Cookie");
        if (cookieHeader == null) return null;
        for (String cookie : cookieHeader.split(";")) {
            String[] parts = cookie.trim().split("=", 2);
            if (parts.length == 2 && "VAULTMIND_SESSION".equals(parts[0])) return parts[1];
        }
        return null;
    }

    private String buildSessionCookie(String token) {
        return "VAULTMIND_SESSION=" + token + "; Path=/; HttpOnly; SameSite=Lax";
    }

    private Map<String, String> readFormData(HttpExchange exchange) throws IOException {
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        return parseUrlEncoded(body);
    }

    private Map<String, String> readQueryParams(HttpExchange exchange) {
        return parseUrlEncoded(exchange.getRequestURI().getRawQuery());
    }

    private Map<String, String> parseUrlEncoded(String raw) {
        if (raw == null || raw.isBlank()) return Collections.emptyMap();
        Map<String, String> values = new HashMap<>();
        for (String pair : raw.split("&")) {
            if (pair.isBlank()) continue;
            String[] parts = pair.split("=", 2);
            String key = URLDecoder.decode(parts[0], StandardCharsets.UTF_8);
            String value = parts.length > 1 ? URLDecoder.decode(parts[1], StandardCharsets.UTF_8) : "";
            values.put(key, value);
        }
        return values;
    }

    private Integer parsePositiveInt(String value) {
        try {
            int parsed = Integer.parseInt(trimmed(value));
            return parsed > 0 ? parsed : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private String trimmed(String v) { return v == null ? "" : v.trim(); }

    private String safeFileName(String fileName) {
        String sanitized = trimmed(fileName)
                .replace("\\", "_")
                .replace("\"", "'")
                .replace("\r", "")
                .replace("\n", "");
        return sanitized.isBlank() ? "vault-file" : sanitized;
    }

    private void redirect(HttpExchange exchange, String loc) throws IOException {
        exchange.getResponseHeaders().set("Location", loc);
        exchange.sendResponseHeaders(302, -1);
        exchange.close();
    }

    private void methodNotAllowed(HttpExchange exchange) throws IOException {
        sendResponse(exchange, 405, HtmlRenderer.renderErrorPage("Method Not Allowed", "Method not supported."), "text/html; charset=UTF-8");
    }

    private void sendResponse(HttpExchange exchange, int code, String body, String type) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", type);
        exchange.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) { os.write(bytes); }
    }

    private void sendFileResponse(HttpExchange exchange, int code, byte[] body, String contentType, String fileName) throws IOException {
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", contentType);
        headers.set("Content-Disposition", "inline; filename=\"" + safeFileName(fileName) + "\"");
        headers.set("Cache-Control", "no-store, private, max-age=0");
        headers.set("Pragma", "no-cache");
        headers.set("X-Content-Type-Options", "nosniff");
        exchange.sendResponseHeaders(code, body.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(body);
        }
    }

    @FunctionalInterface
    private interface RouteHandler { void handle(HttpExchange e) throws Exception; }
}

/**
 * Session Management
 */
class SessionManager {
    private static final Duration SESSION_TTL = Duration.ofHours(8);
    private final SecureRandom secureRandom = new SecureRandom();
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private final ScheduledExecutorService cleanupExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "vaultmind-session-cleanup");
        thread.setDaemon(true);
        return thread;
    });

    public SessionManager() {
        cleanupExecutor.scheduleAtFixedRate(this::purgeExpiredSessions, 1, 1, TimeUnit.MINUTES);
    }

    public Session createSession(User user) {
        purgeExpiredSessions();
        byte[] tokenBytes = new byte[32];
        secureRandom.nextBytes(tokenBytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
        Session session = new Session(token, user.getId(), user.getUsername(), user.getRole(), Instant.now());
        sessions.put(token, session);
        return session;
    }

    public Session getSession(String token) {
        purgeExpiredSessions();
        Session s = token == null ? null : sessions.get(token);
        if (s != null) s.lastSeen = Instant.now();
        return s;
    }

    public void removeSession(String t) {
        if (t == null) return;
        Session removed = sessions.remove(t);
        if (removed != null) removed.clearSensitiveData();
    }

    public DecryptedFile getOrCreateDecryptedFile(Session session, VaultFile file, String secret) throws Exception {
        DecryptedFile cached = session.decryptedFiles.get(file.getId());
        if (cached != null) {
            return cached;
        }

        if (file.getFileContent() == null) {
            throw new IllegalStateException("No encrypted content is stored for this file.");
        }

        byte[] decryptedContent = EncryptionService.decrypt(file.getFileContent(), secret);
        DecryptedFile created = new DecryptedFile(
                file.getFileName(),
                detectContentType(file.getFileName(), decryptedContent),
                decryptedContent
        );
        DecryptedFile existing = session.decryptedFiles.putIfAbsent(file.getId(), created);
        if (existing != null) {
            created.destroy();
            return existing;
        }
        return created;
    }

    private void purgeExpiredSessions() {
        Instant now = Instant.now();
        for (Map.Entry<String, Session> entry : sessions.entrySet()) {
            Session session = entry.getValue();
            if (session.isExpired(now) && sessions.remove(entry.getKey(), session)) {
                session.clearSensitiveData();
            }
        }
    }

    private String detectContentType(String fileName, byte[] content) {
        String detected = URLConnection.guessContentTypeFromName(fileName);
        if (detected == null && content.length > 0) {
            try (ByteArrayInputStream input = new ByteArrayInputStream(content)) {
                detected = URLConnection.guessContentTypeFromStream(input);
            } catch (IOException ignored) {
                detected = null;
            }
        }
        return detected == null ? "application/octet-stream" : detected;
    }

    public static class Session {
        private final String token;
        private final int userId;
        private final String username;
        private final String role;
        private final Map<Integer, DecryptedFile> decryptedFiles = new ConcurrentHashMap<>();
        private Instant lastSeen;

        private Session(String t, int id, String u, String r, Instant now) {
            this.token = t; this.userId = id; this.username = u; this.role = r; this.lastSeen = now;
        }
        private boolean isExpired(Instant now) { return lastSeen.plus(SESSION_TTL).isBefore(now); }
        private void clearSensitiveData() {
            for (DecryptedFile file : decryptedFiles.values()) {
                file.destroy();
            }
            decryptedFiles.clear();
        }
        public String getToken() { return token; }
        public int getUserId() { return userId; }
        public String getUsername() { return username; }
        public String getRole() { return role; }
    }

    public static class DecryptedFile {
        private final String fileName;
        private final String contentType;
        private final byte[] content;

        private DecryptedFile(String fileName, String contentType, byte[] content) {
            this.fileName = fileName;
            this.contentType = contentType;
            this.content = content;
        }

        private void destroy() {
            Arrays.fill(content, (byte) 0);
        }

        public String getFileName() { return fileName; }
        public String getContentType() { return contentType; }
        public byte[] getContent() { return content; }
    }
}
