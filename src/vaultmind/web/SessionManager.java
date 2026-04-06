package vaultmind.web;

import vaultmind.model.User;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class SessionManager {
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
        if (token == null || token.isBlank()) {
            return null;
        }

        Session session = sessions.get(token);
        if (session == null) {
            return null;
        }

        if (session.lastSeen.plus(SESSION_TTL).isBefore(Instant.now())) {
            sessions.remove(token);
            return null;
        }

        session.lastSeen = Instant.now();
        return session;
    }

    public void removeSession(String token) {
        if (token != null && !token.isBlank()) {
            sessions.remove(token);
        }
    }

    public static class Session {
        private final String token;
        private final int userId;
        private final String username;
        private final String role;
        private final Instant createdAt;
        private Instant lastSeen;

        private Session(String token, int userId, String username, String role, Instant createdAt) {
            this.token = token;
            this.userId = userId;
            this.username = username;
            this.role = role;
            this.createdAt = createdAt;
            this.lastSeen = createdAt;
        }

        public String getToken() {
            return token;
        }

        public int getUserId() {
            return userId;
        }

        public String getUsername() {
            return username;
        }

        public String getRole() {
            return role;
        }

        public Instant getCreatedAt() {
            return createdAt;
        }
    }
}
