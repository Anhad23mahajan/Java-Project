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
import java.security.SecureRandom;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;

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
        if (body.isBlank()) return Collections.emptyMap();
        Map<String, String> values = new HashMap<>();
        for (String pair : body.split("&")) {
            String[] parts = pair.split("=", 2);
            String key = URLDecoder.decode(parts[0], StandardCharsets.UTF_8);
            String value = parts.length > 1 ? URLDecoder.decode(parts[1], StandardCharsets.UTF_8) : "";
            values.put(key, value);
        }
        return values;
    }

    private String trimmed(String v) { return v == null ? "" : v.trim(); }

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

    public Session createSession(User user) {
        byte[] tokenBytes = new byte[32];
        secureRandom.nextBytes(tokenBytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
        Session session = new Session(token, user.getId(), user.getUsername(), user.getRole(), Instant.now());
        sessions.put(token, session);
        return session;
    }

    public Session getSession(String token) {
        Session s = token == null ? null : sessions.get(token);
        if (s != null && s.lastSeen.plus(SESSION_TTL).isBefore(Instant.now())) {
            sessions.remove(token);
            return null;
        }
        if (s != null) s.lastSeen = Instant.now();
        return s;
    }

    public void removeSession(String t) { if (t != null) sessions.remove(t); }

    public static class Session {
        private final String token;
        private final int userId;
        private final String username;
        private final String role;
        private Instant lastSeen;

        private Session(String t, int id, String u, String r, Instant now) {
            this.token = t; this.userId = id; this.username = u; this.role = r; this.lastSeen = now;
        }
        public String getToken() { return token; }
        public int getUserId() { return userId; }
        public String getUsername() { return username; }
        public String getRole() { return role; }
    }
}

/**
 * UI Rendering
 */
class HtmlRenderer {
    public static String renderLoginPage(String msg, boolean ok) {
        String status = msg == null ? "" : "<div class=\"status " + (ok ? "success" : "error") + "\">" + esc(msg) + "</div>";
        return layout("Login", "<div class=\"panel auth-panel\"><h1>VaultMind</h1>" + status + 
            "<form method=\"post\" action=\"/login\" class=\"stack\">" +
            "<label>User<input type=\"text\" name=\"username\" required></label>" +
            "<label>Pass<input type=\"password\" name=\"password\" required></label>" +
            "<button type=\"submit\">Log In</button></form><p><a href=\"/register\">Register</a></p></div>", null);
    }

    public static String renderRegisterPage(String msg) {
        String status = msg == null ? "" : "<div class=\"status error\">" + esc(msg) + "</div>";
        return layout("Register", "<div class=\"panel auth-panel\"><h1>Register</h1>" + status + 
            "<form method=\"post\" action=\"/register\" class=\"stack\">" +
            "<label>User<input type=\"text\" name=\"username\" required></label>" +
            "<label>Pass<input type=\"password\" name=\"password\" required></label>" +
            "<button type=\"submit\">Join</button></form><p><a href=\"/login\">Back</a></p></div>", null);
    }

    public static String renderUserDashboard(SessionManager.Session s, List<VaultFile> files, String msg, boolean ok) {
        StringBuilder rows = new StringBuilder();
        for (VaultFile f : files) {
            String info = f.getFileContent() != null ? "In DB (" + f.getFileContent().length + "B)" : f.getEncryptedPath();
            rows.append("<tr><td>").append(esc(f.getFileName())).append("</td><td><code>").append(esc(info)).append("</code></td><td>").append(esc(f.getUploadedAt())).append("</td></tr>");
        }
        return layout("Dashboard", header(s, "Dashboard") + "<div class=\"grid\"><div class=\"panel\"><h2>Upload</h2>" +
            (msg != null ? "<div class=\"status " + (ok ? "success" : "error") + "\">" + esc(msg) + "</div>" : "") +
            "<form method=\"post\" action=\"/files\" enctype=\"multipart/form-data\" class=\"stack\"><input type=\"file\" name=\"file\" required><button type=\"submit\">Upload</button></form></div>" +
            "<div class=\"panel wide\"><h2>My Files</h2><table><thead><tr><th>File</th><th>Info</th><th>Date</th></tr></thead><tbody>" + 
            (rows.length() == 0 ? "<tr><td colspan=\"3\">Empty</td></tr>" : rows) + "</tbody></table></div></div>", s);
    }

    public static String renderAdminDashboard(SessionManager.Session s, List<User> users, List<VaultFile> files) {
        StringBuilder uRows = new StringBuilder(), fRows = new StringBuilder();
        for (User u : users) uRows.append("<tr><td>").append(u.getId()).append("</td><td>").append(esc(u.getUsername())).append("</td><td>").append(esc(u.getRole())).append("</td></tr>");
        for (VaultFile f : files) fRows.append("<tr><td>").append(esc(f.getOwnerUsername())).append("</td><td>").append(esc(f.getFileName())).append("</td><td>").append(esc(f.getUploadedAt())).append("</td></tr>");
        return layout("Admin", header(s, "Admin") + "<div class=\"grid\"><div class=\"panel wide\"><h2>Users</h2><table><thead><tr><th>ID</th><th>User</th><th>Role</th></tr></thead><tbody>" + uRows + "</tbody></table></div>" +
            "<div class=\"panel wide\"><h2>All Files</h2><table><thead><tr><th>Owner</th><th>File</th><th>Date</th></tr></thead><tbody>" + fRows + "</tbody></table></div></div>", s);
    }

    public static String renderErrorPage(String t, String m) {
        return layout(t, "<div class=\"panel auth-panel\"><h1>" + esc(t) + "</h1><p>" + esc(m) + "</p><a href=\"/\">Home</a></div>", null);
    }

    private static String header(SessionManager.Session s, String t) {
        return "<header class=\"app-header\"><div><span>" + esc(s.getUsername()) + " (" + esc(s.getRole()) + ")</span><h1>" + esc(t) + "</h1></div><a class=\"ghost-button\" href=\"/logout\">Log Out</a></header>";
    }

    private static String layout(String t, String b, SessionManager.Session s) {
        return "<!DOCTYPE html><html><head><title>" + esc(t) + "</title><style>" +
            ":root{--bg:#f5efe5;--ink:#1f2a2e;--panel:#fffaf3;--line:#d9c8b2;--accent:#b5522e;--muted:#6d6258;--ok:#1f7a52;--error:#9f2f2f;}" +
            "body{margin:0;font-family:sans-serif;background:var(--bg);color:var(--ink);}.panel{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:20px;margin-bottom:20px;}" +
            ".grid{display:grid;grid-template-columns:1fr 2fr;gap:20px;width:min(1000px,95%);margin:0 auto;}.wide{grid-column:1/-1;}.stack{display:grid;gap:10px;}" +
            "button,.ghost-button{padding:10px;border-radius:8px;border:none;background:var(--accent);color:#fff;cursor:pointer;text-decoration:none;display:inline-block;text-align:center;}" +
            "input{padding:10px;border:1px solid var(--line);border-radius:8px;}table{width:100%;border-collapse:collapse;}th,td{padding:10px;border-bottom:1px solid var(--line);text-align:left;}" +
            ".status{padding:10px;border-radius:8px;margin-bottom:10px;font-weight:bold;}.success{background:#dcfce7;color:var(--ok);}.error{background:#fee2e2;color:var(--error);}" +
            ".app-header{width:min(1000px,95%);margin:0 auto;padding:20px 0;display:flex;justify-content:space-between;align-items:center;}" +
            ".auth-panel{max-width:400px;margin:100px auto;text-align:center;}</style></head><body>" + (s==null?b:"<main>"+b+"</main>") + "</body></html>";
    }

    private static String esc(String v) { return v==null?"":v.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;"); }
}
