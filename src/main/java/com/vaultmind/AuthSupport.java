package com.vaultmind;

import at.favre.lib.crypto.bcrypt.BCrypt;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.sql.SQLException;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

//  ABSTRACTION: AuthService Interface 
interface AuthService {
    Auth.Session login(String username, String password) throws Exception;
    Auth.Session signup(String username, String password) throws Exception;
    void changePassword(int userId, String currentPassword, String newPassword) throws Exception;
    void updateAdmin(int userId, String username, String password) throws SQLException;
    void deleteUser(int userId) throws SQLException;
}

//  INHERITANCE: DatabaseAuthService implements AuthService 
final class DatabaseAuthService implements AuthService {
    private final Database db;

    DatabaseAuthService(Database db) {
        this.db = db;
    }

    @Override
    public Auth.Session login(String username, String password) throws Exception {
        String cleanUsername = require(username, 3, "Username");
        String cleanPassword = requirePresent(password, "Password");

        Auth.Session session = db.queryOne(
            "SELECT id, username, password_hash, role FROM users WHERE username = ?",
            rs -> {
                BCrypt.Result result = BCrypt.verifyer().verify(cleanPassword.toCharArray(), rs.getString("password_hash"));
                if (!result.verified) throw new ApiException(401, "Invalid credentials.");
                return new Auth.Session(rs.getInt("id"), rs.getString("username"), rs.getString("role"));
            },
            cleanUsername
        );

        if (session == null) throw new ApiException(401, "Invalid credentials.");
        return session;
    }

    @Override
    public Auth.Session signup(String username, String password) throws Exception {
        String cleanUsername = require(username, 3, "Username");
        String cleanPassword = require(password, 6, "Password");
        ensureUsernameAvailable(cleanUsername, null);

        String role = db.exists("SELECT 1 FROM users WHERE role = 'admin'") ? "user" : "admin";
        long id = db.insert(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            cleanUsername,
            BCrypt.withDefaults().hashToString(12, cleanPassword.toCharArray()),
            role
        );
        return new Auth.Session((int) id, cleanUsername, role);
    }

    @Override
    public void changePassword(int userId, String currentPassword, String newPassword) throws Exception {
        String cleanCurrentPassword = requirePresent(currentPassword, "Current password");
        String cleanNewPassword = require(newPassword, 6, "New password");
        String hash = db.queryOne("SELECT password_hash FROM users WHERE id = ?", rs -> rs.getString(1), userId);
        if (hash == null) throw new ApiException(404, "User not found.");

        if (!BCrypt.verifyer().verify(cleanCurrentPassword.toCharArray(), hash).verified) {
            throw new ApiException(401, "Incorrect password.");
        }

        db.update("UPDATE users SET password_hash = ? WHERE id = ?", 
            BCrypt.withDefaults().hashToString(12, cleanNewPassword.toCharArray()), userId);
    }

    @Override
    public void updateAdmin(int userId, String username, String password) throws SQLException {
        String cleanUsername = require(username, 3, "Username");
        ensureUsernameAvailable(cleanUsername, userId);
        db.update("UPDATE users SET username = ?, password_hash = ? WHERE id = ?",
            cleanUsername, BCrypt.withDefaults().hashToString(12, password.toCharArray()), userId);
    }

    @Override
    public void deleteUser(int userId) throws SQLException {
        if (db.update("DELETE FROM users WHERE id = ?", userId) == 0) throw new ApiException(404, "Not found.");
    }

    private void ensureUsernameAvailable(String username, Integer excludedId) throws SQLException {
        boolean exists = excludedId == null 
            ? db.exists("SELECT 1 FROM users WHERE username = ?", username)
            : db.exists("SELECT 1 FROM users WHERE username = ? AND id <> ?", username, excludedId);
        if (exists) throw new ValidationException("Username taken.");
    }

    private String require(String val, int min, String name) {
        if (val == null || val.trim().length() < min) throw new ValidationException(name + " too short.");
        return val.trim();
    }

    private String requirePresent(String val, String name) {
        if (val == null || val.trim().isEmpty()) throw new ValidationException(name + " required.");
        return val.trim();
    }
}

//  POLYMORPHISM: Interface implementation handled in constructor 
final class Auth {
    private Auth() {}
    record Session(int id, String username, String role) {
        boolean isAdmin() { return "admin".equalsIgnoreCase(role); }
    }
}

final class Sessions {
    private static final Map<String, Auth.Session> ACTIVE = new ConcurrentHashMap<>();
    private static final String COOKIE = "VAULTMIND_SESSION";

    static void start(HttpServletResponse res, Auth.Session s) {
        String token = UUID.randomUUID().toString();
        ACTIVE.put(token, s);
        Cookie c = new Cookie(COOKIE, token);
        c.setPath("/");
        c.setHttpOnly(true);
        res.addCookie(c);
    }

    static void end(HttpServletRequest req, HttpServletResponse res) {
        String token = token(req);
        if (token != null) ACTIVE.remove(token);
        Cookie c = new Cookie(COOKIE, "");
        c.setPath("/");
        c.setMaxAge(0);
        res.addCookie(c);
    }

    static Auth.Session current(HttpServletRequest req) {
        String t = token(req);
        return t == null ? null : ACTIVE.get(t);
    }

    static Auth.Session require(HttpServletRequest req) {
        Auth.Session s = current(req);
        if (s == null) throw new ApiException(401, "Not logged in.");
        return s;
    }

    private static String token(HttpServletRequest req) {
        Cookie[] cs = req.getCookies();
        if (cs != null) for (Cookie c : cs) if (COOKIE.equals(c.getName())) return c.getValue();
        return null;
    }
}
