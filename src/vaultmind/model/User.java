package vaultmind.model;

public class User {
    private final int id;
    private final String username;
    private final String passwordHash;
    private final String role;
    private final String createdAt;

    public User(int id, String username, String passwordHash, String role, String createdAt) {
        this.id = id;
        this.username = username;
        this.passwordHash = passwordHash;
        this.role = role;
        this.createdAt = createdAt;
    }

    public int getId() { return id; }
    public String getUsername() { return username; }
    public String getPasswordHash() { return passwordHash; }
    public String getRole() { return role; }
    public String getCreatedAt() { return createdAt; }
}
