package vaultmind.web;

import vaultmind.model.User;
import vaultmind.model.VaultFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

final class HtmlRenderer {
    private static final Path TEMPLATE_DIR = Path.of("src", "vaultmind", "web", "templates");

    private HtmlRenderer() {
    }

    public static String renderLoginPage(String msg, boolean ok) {
        Map<String, String> values = new HashMap<>();
        values.put("status_class", statusClass(msg, ok));
        values.put("status_message", esc(msg));
        return renderTemplate("login.html", values);
    }

    public static String renderRegisterPage(String msg) {
        Map<String, String> values = new HashMap<>();
        values.put("status_class", statusClass(msg, false));
        values.put("status_message", esc(msg));
        return renderTemplate("register.html", values);
    }

    public static String renderUserDashboard(SessionManager.Session session, List<VaultFile> files, String msg, boolean ok) {
        Map<String, String> values = new HashMap<>();
        values.put("username", esc(session.getUsername()));
        values.put("role", esc(titleCase(session.getRole())));
        values.put("file_count", Integer.toString(files.size()));
        values.put("storage_total", esc(formatBytes(totalEncryptedBytes(files))));
        values.put("recent_upload", esc(files.isEmpty() ? "No uploads yet" : displayTimestamp(files.get(0).getUploadedAt())));
        values.put("status_class", statusClass(msg, ok));
        values.put("status_message", esc(msg));
        values.put("files_json", buildUserFilesJson(files));
        return renderTemplate("user_dashboard.html", values);
    }

    public static String renderAdminDashboard(SessionManager.Session session, List<User> users, List<VaultFile> files) {
        Map<String, String> values = new HashMap<>();
        values.put("username", esc(session.getUsername()));
        values.put("role", esc(titleCase(session.getRole())));
        values.put("user_count", Integer.toString(users.size()));
        values.put("admin_count", Integer.toString(countAdmins(users)));
        values.put("file_count", Integer.toString(files.size()));
        values.put("encrypted_total", esc(formatBytes(totalEncryptedBytes(files))));
        values.put("users_json", buildAdminUsersJson(users));
        values.put("files_json", buildAdminFilesJson(files));
        return renderTemplate("admin_dashboard.html", values);
    }

    public static String renderErrorPage(String title, String message) {
        Map<String, String> values = new HashMap<>();
        values.put("title", esc(title));
        values.put("message", esc(message));
        return renderTemplate("error.html", values);
    }

    private static String buildUserFilesJson(List<VaultFile> files) {
        StringBuilder json = new StringBuilder("[");
        boolean first = true;
        for (VaultFile file : files) {
            if (!first) {
                json.append(',');
            }
            first = false;

            String info = file.getFileContent() != null
                    ? "Encrypted in PostgreSQL (" + formatBytes(file.getFileContent().length) + ")"
                    : file.getEncryptedPath();

            json.append('{')
                    .append("\"id\":").append(file.getId()).append(',')
                    .append("\"name\":\"").append(jsonEscape(file.getFileName())).append("\",")
                    .append("\"info\":\"").append(jsonEscape(info)).append("\",")
                    .append("\"uploaded\":\"").append(jsonEscape(displayTimestamp(file.getUploadedAt()))).append("\",")
                    .append("\"viewUrl\":\"").append(jsonEscape("/files/view?id=" + file.getId())).append("\"")
                    .append('}');
        }
        return json.append(']').toString();
    }

    private static String buildAdminUsersJson(List<User> users) {
        StringBuilder json = new StringBuilder("[");
        boolean first = true;
        for (User user : users) {
            if (!first) {
                json.append(',');
            }
            first = false;

            json.append('{')
                    .append("\"id\":").append(user.getId()).append(',')
                    .append("\"username\":\"").append(jsonEscape(user.getUsername())).append("\",")
                    .append("\"role\":\"").append(jsonEscape(titleCase(user.getRole()))).append("\",")
                    .append("\"roleType\":\"").append(jsonEscape(user.getRole())).append("\",")
                    .append("\"created\":\"").append(jsonEscape(displayTimestamp(user.getCreatedAt()))).append("\"")
                    .append('}');
        }
        return json.append(']').toString();
    }

    private static String buildAdminFilesJson(List<VaultFile> files) {
        StringBuilder json = new StringBuilder("[");
        boolean first = true;
        for (VaultFile file : files) {
            if (!first) {
                json.append(',');
            }
            first = false;

            json.append('{')
                    .append("\"owner\":\"").append(jsonEscape(file.getOwnerUsername())).append("\",")
                    .append("\"userId\":").append(file.getUserId()).append(',')
                    .append("\"name\":\"").append(jsonEscape(file.getFileName())).append("\",")
                    .append("\"size\":\"").append(jsonEscape(file.getFileContent() == null ? "No blob" : formatBytes(file.getFileContent().length))).append("\",")
                    .append("\"uploaded\":\"").append(jsonEscape(displayTimestamp(file.getUploadedAt()))).append("\"")
                    .append('}');
        }
        return json.append(']').toString();
    }

    private static String statusClass(String message, boolean ok) {
        if (message == null || message.isBlank()) {
            return "";
        }
        return ok ? "success" : "error";
    }

    private static int countAdmins(List<User> users) {
        int total = 0;
        for (User user : users) {
            if ("admin".equalsIgnoreCase(user.getRole())) {
                total++;
            }
        }
        return total;
    }

    private static long totalEncryptedBytes(List<VaultFile> files) {
        long total = 0L;
        for (VaultFile file : files) {
            if (file.getFileContent() != null) {
                total += file.getFileContent().length;
            }
        }
        return total;
    }

    private static String displayTimestamp(String raw) {
        if (raw == null || raw.isBlank()) {
            return "Unknown";
        }
        return raw.replace('T', ' ');
    }

    private static String titleCase(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        String lower = value.toLowerCase();
        return Character.toUpperCase(lower.charAt(0)) + lower.substring(1);
    }

    private static String formatBytes(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        }

        double value = bytes;
        String[] units = {"KB", "MB", "GB", "TB"};
        int unitIndex = -1;
        while (value >= 1024 && unitIndex < units.length - 1) {
            value /= 1024;
            unitIndex++;
        }

        if (value >= 100 || value % 1 == 0) {
            return String.format("%.0f %s", value, units[unitIndex]);
        }
        return String.format("%.1f %s", value, units[unitIndex]);
    }

    private static String renderTemplate(String templateName, Map<String, String> values) {
        try {
            String html = Files.readString(TEMPLATE_DIR.resolve(templateName));
            for (Map.Entry<String, String> entry : values.entrySet()) {
                html = html.replace("{{" + entry.getKey() + "}}", entry.getValue());
            }
            return html.replaceAll("\\{\\{[a-zA-Z0-9_]+}}", "");
        } catch (IOException e) {
            return "Template error: " + e.getMessage();
        }
    }

    private static String jsonEscape(String value) {
        if (value == null) {
            return "";
        }

        StringBuilder escaped = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            switch (ch) {
                case '\\':
                    escaped.append("\\\\");
                    break;
                case '"':
                    escaped.append("\\\"");
                    break;
                case '\b':
                    escaped.append("\\b");
                    break;
                case '\f':
                    escaped.append("\\f");
                    break;
                case '\n':
                    escaped.append("\\n");
                    break;
                case '\r':
                    escaped.append("\\r");
                    break;
                case '\t':
                    escaped.append("\\t");
                    break;
                case '<':
                    escaped.append("\\u003c");
                    break;
                case '>':
                    escaped.append("\\u003e");
                    break;
                case '&':
                    escaped.append("\\u0026");
                    break;
                default:
                    if (ch < 0x20) {
                        escaped.append(String.format("\\u%04x", (int) ch));
                    } else {
                        escaped.append(ch);
                    }
                    break;
            }
        }
        return escaped.toString();
    }

    private static String esc(String value) {
        if (value == null) {
            return "";
        }
        return value
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }
}
