package vaultmind.model;

public class VaultFile {
    private final int id;
    private final int userId;
    private final String ownerUsername;
    private final String fileName;
    private final String encryptedPath;
    private final byte[] fileContent;
    private final String uploadedAt;

    public VaultFile(int id, int userId, String ownerUsername, String fileName, String encryptedPath, byte[] fileContent, String uploadedAt) {
        this.id = id;
        this.userId = userId;
        this.ownerUsername = ownerUsername;
        this.fileName = fileName;
        this.encryptedPath = encryptedPath;
        this.fileContent = fileContent;
        this.uploadedAt = uploadedAt;
    }

    public int getId() { return id; }
    public int getUserId() { return userId; }
    public String getOwnerUsername() { return ownerUsername; }
    public String getFileName() { return fileName; }
    public String getEncryptedPath() { return encryptedPath; }
    public byte[] getFileContent() { return fileContent; }
    public String getUploadedAt() { return uploadedAt; }
}
