package com.localai;

import at.favre.lib.crypto.bcrypt.BCrypt;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.sql.SQLException;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

final class Auth {
    private Auth() {
    }

    static Session login(String username, String password) throws Exception {
        String cleanUsername = require(username, 3, "Username");
        String cleanPassword = requirePresent(password, "Password");

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
        ensureUsernameAvailable(cleanUsername, null);

        String role = DB.exists("SELECT 1 FROM users WHERE role = 'admin'") ? "user" : "admin";
        long id = DB.insert(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            cleanUsername,
            BCrypt.withDefaults().hashToString(12, cleanPassword.toCharArray()),
            role
        );
        return new Session((int) id, cleanUsername, role);
    }

    static void changePassword(int userId, String currentPassword, String newPassword) throws Exception {
        String cleanCurrentPassword = requirePresent(currentPassword, "Current password");
        String cleanNewPassword = require(newPassword, 6, "New password");
        String passwordHash = DB.queryOne(
            "SELECT password_hash FROM users WHERE id = ?",
            rs -> rs.getString("password_hash"),
            userId
        );

        if (passwordHash == null) {
            throw new ApiException(404, "User not found.");
        }

        BCrypt.Result result = BCrypt.verifyer().verify(cleanCurrentPassword.toCharArray(), passwordHash);
        if (!result.verified) {
            throw new ApiException(401, "Current password is incorrect.");
        }

        DB.update(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            BCrypt.withDefaults().hashToString(12, cleanNewPassword.toCharArray()),
            userId
        );
    }

    static void updateAdmin(int userId, String username, String password) throws SQLException {
        String cleanUsername = require(username, 3, "Username");
        String cleanPassword = require(password, 6, "Password");
        ensureUsernameAvailable(cleanUsername, userId);
        DB.update(
            "UPDATE users SET username = ?, password_hash = ? WHERE id = ?",
            cleanUsername,
            BCrypt.withDefaults().hashToString(12, cleanPassword.toCharArray()),
            userId
        );
    }

    private static void ensureUsernameAvailable(String username, Integer excludedUserId) throws SQLException {
        boolean exists = excludedUserId == null
            ? DB.exists("SELECT 1 FROM users WHERE username = ?", username)
            : DB.exists("SELECT 1 FROM users WHERE username = ? AND id <> ?", username, excludedUserId);
        if (exists) {
            throw new ApiException(400, "Username already exists.");
        }
    }

    private static String require(String value, int minLength, String name) {
        String clean = value == null ? "" : value.trim();
        if (clean.length() < minLength) {
            throw new ApiException(400, name + " must be at least " + minLength + " characters.");
        }
        return clean;
    }

    private static String requirePresent(String value, String name) {
        String clean = value == null ? "" : value.trim();
        if (clean.isEmpty()) {
            throw new ApiException(400, name + " is required.");
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
        cookie.setSecure(false);
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
