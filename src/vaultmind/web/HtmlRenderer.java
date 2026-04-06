package vaultmind.web;

import vaultmind.model.User;
import vaultmind.model.VaultFile;

import java.util.List;

public final class HtmlRenderer {
    private HtmlRenderer() {
    }

    public static String renderLoginPage(String message, boolean success) {
        String status = message == null || message.isBlank()
                ? ""
                : "<div class=\"status " + (success ? "success" : "error") + "\">" + escape(message) + "</div>";
        String body = ""
                + "<section class=\"hero\">"
                + "<div class=\"panel auth-panel\">"
                + "<span class=\"eyebrow\">VaultMind / Localhost only</span>"
                + "<h1>Private vault access</h1>"
                + "<p>Run authentication, role checks, and document metadata management entirely on your machine.</p>"
                + status
                + "<form method=\"post\" action=\"/login\" class=\"stack\">"
                + "<label>Username<input type=\"text\" name=\"username\" autocomplete=\"username\" required></label>"
                + "<label>Password<input type=\"password\" name=\"password\" autocomplete=\"current-password\" required></label>"
                + "<button type=\"submit\">Log In</button>"
                + "</form>"
                + "<p class=\"muted\">Need an account? <a href=\"/register\">Create one</a></p>"
                + "</div>"
                + "<div class=\"panel side-panel\">"
                + "<h2>What this app is now</h2>"
                + "<ul>"
                + "<li>Local web interface bound to <code>127.0.0.1</code></li>"
                + "<li>PostgreSQL-backed user accounts and roles</li>"
                + "<li>Separate admin and user dashboards</li>"
                + "</ul>"
                + "</div>"
                + "</section>";
        return layout("VaultMind Login", body, null);
    }

    public static String renderRegisterPage(String message) {
        String status = message == null || message.isBlank()
                ? ""
                : "<div class=\"status error\">" + escape(message) + "</div>";
        String body = ""
                + "<section class=\"hero\">"
                + "<div class=\"panel auth-panel\">"
                + "<span class=\"eyebrow\">VaultMind / Register</span>"
                + "<h1>Create a local account</h1>"
                + "<p>New signups are created as regular users. Admins should be seeded locally.</p>"
                + status
                + "<form method=\"post\" action=\"/register\" class=\"stack\">"
                + "<label>Username<input type=\"text\" name=\"username\" autocomplete=\"username\" required></label>"
                + "<label>Password<input type=\"password\" name=\"password\" autocomplete=\"new-password\" required></label>"
                + "<button type=\"submit\">Create Account</button>"
                + "</form>"
                + "<p class=\"muted\"><a href=\"/login\">Back to login</a></p>"
                + "</div>"
                + "</section>";
        return layout("VaultMind Register", body, null);
    }

    public static String renderUserDashboard(SessionManager.Session session, List<VaultFile> files, String message, boolean success) {
        String status = message == null || message.isBlank()
                ? ""
                : "<div class=\"status " + (success ? "success" : "error") + "\">" + escape(message) + "</div>";
        StringBuilder rows = new StringBuilder();

        if (files.isEmpty()) {
            rows.append("<tr><td colspan=\"3\">No vault entries yet.</td></tr>");
        } else {
            for (VaultFile file : files) {
                rows.append("<tr>")
                        .append("<td>").append(escape(file.getFileName())).append("</td>")
                        .append("<td><code>").append(escape(file.getEncryptedPath())).append("</code></td>")
                        .append("<td>").append(escape(file.getUploadedAt())).append("</td>")
                        .append("</tr>");
            }
        }

        String body = ""
                + header(session, "User Dashboard", "Store and review your local vault metadata.")
                + "<section class=\"grid\">"
                + "<div class=\"panel\">"
                + "<h2>Add vault record</h2>"
                + "<p class=\"muted\">This currently stores file metadata only. Encryption and document chat are separate next steps.</p>"
                + status
                + "<form method=\"post\" action=\"/files\" class=\"stack\">"
                + "<label>File name<input type=\"text\" name=\"fileName\" placeholder=\"report.pdf\" required></label>"
                + "<label>Encrypted path<input type=\"text\" name=\"encryptedPath\" placeholder=\"C:\\\\vault\\\\report.pdf.enc\" required></label>"
                + "<button type=\"submit\">Save Record</button>"
                + "</form>"
                + "</div>"
                + "<div class=\"panel wide\">"
                + "<h2>My vault records</h2>"
                + "<table>"
                + "<thead><tr><th>File</th><th>Encrypted Path</th><th>Uploaded</th></tr></thead>"
                + "<tbody>" + rows + "</tbody>"
                + "</table>"
                + "</div>"
                + "</section>";
        return layout("VaultMind Dashboard", body, session);
    }

    public static String renderAdminDashboard(SessionManager.Session session, List<User> users, List<VaultFile> files) {
        StringBuilder userRows = new StringBuilder();
        StringBuilder fileRows = new StringBuilder();

        if (users.isEmpty()) {
            userRows.append("<tr><td colspan=\"4\">No users found.</td></tr>");
        } else {
            for (User user : users) {
                userRows.append("<tr>")
                        .append("<td>").append(user.getId()).append("</td>")
                        .append("<td>").append(escape(user.getUsername())).append("</td>")
                        .append("<td>").append(escape(user.getRole())).append("</td>")
                        .append("<td>").append(escape(user.getCreatedAt())).append("</td>")
                        .append("</tr>");
            }
        }

        if (files.isEmpty()) {
            fileRows.append("<tr><td colspan=\"5\">No vault records found.</td></tr>");
        } else {
            for (VaultFile file : files) {
                fileRows.append("<tr>")
                        .append("<td>").append(file.getId()).append("</td>")
                        .append("<td>").append(escape(file.getOwnerUsername())).append("</td>")
                        .append("<td>").append(escape(file.getFileName())).append("</td>")
                        .append("<td><code>").append(escape(file.getEncryptedPath())).append("</code></td>")
                        .append("<td>").append(escape(file.getUploadedAt())).append("</td>")
                        .append("</tr>");
            }
        }

        String body = ""
                + header(session, "Admin Dashboard", "Monitor local users and vault records without exposing the app outside localhost.")
                + "<section class=\"grid admin-grid\">"
                + "<div class=\"panel stat\">"
                + "<span class=\"eyebrow\">Users</span>"
                + "<strong>" + users.size() + "</strong>"
                + "</div>"
                + "<div class=\"panel stat\">"
                + "<span class=\"eyebrow\">Vault records</span>"
                + "<strong>" + files.size() + "</strong>"
                + "</div>"
                + "<div class=\"panel wide\">"
                + "<h2>All users</h2>"
                + "<table>"
                + "<thead><tr><th>ID</th><th>Username</th><th>Role</th><th>Joined</th></tr></thead>"
                + "<tbody>" + userRows + "</tbody>"
                + "</table>"
                + "</div>"
                + "<div class=\"panel wide\">"
                + "<h2>All vault records</h2>"
                + "<table>"
                + "<thead><tr><th>ID</th><th>Owner</th><th>File</th><th>Encrypted Path</th><th>Uploaded</th></tr></thead>"
                + "<tbody>" + fileRows + "</tbody>"
                + "</table>"
                + "</div>"
                + "</section>";
        return layout("VaultMind Admin", body, session);
    }

    public static String renderErrorPage(String title, String message) {
        String body = ""
                + "<section class=\"hero\">"
                + "<div class=\"panel auth-panel\">"
                + "<span class=\"eyebrow\">VaultMind / Error</span>"
                + "<h1>" + escape(title) + "</h1>"
                + "<p>" + escape(message) + "</p>"
                + "<p class=\"muted\"><a href=\"/\">Return home</a></p>"
                + "</div>"
                + "</section>";
        return layout(title, body, null);
    }

    private static String header(SessionManager.Session session, String title, String subtitle) {
        return ""
                + "<header class=\"app-header\">"
                + "<div>"
                + "<span class=\"eyebrow\">Logged in as " + escape(session.getUsername()) + " / " + escape(session.getRole()) + "</span>"
                + "<h1>" + escape(title) + "</h1>"
                + "<p>" + escape(subtitle) + "</p>"
                + "</div>"
                + "<a class=\"ghost-button\" href=\"/logout\">Log Out</a>"
                + "</header>";
    }

    private static String layout(String title, String body, SessionManager.Session session) {
        return "<!DOCTYPE html>"
                + "<html lang=\"en\">"
                + "<head>"
                + "<meta charset=\"UTF-8\">"
                + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
                + "<title>" + escape(title) + "</title>"
                + "<style>"
                + ":root{color-scheme:light;--bg:#f5efe5;--ink:#1f2a2e;--panel:#fffaf3;--line:#d9c8b2;--accent:#b5522e;--accent-dark:#8f3d20;--soft:#ead8c4;--muted:#6d6258;--ok:#1f7a52;--error:#9f2f2f;}"
                + "*{box-sizing:border-box;}body{margin:0;font-family:Segoe UI,system-ui,sans-serif;background:radial-gradient(circle at top,#fff7ed 0,#f5efe5 40%,#efe5d6 100%);color:var(--ink);}"
                + "a{color:var(--accent-dark);text-decoration:none;}a:hover{text-decoration:underline;}"
                + ".hero,.page{width:min(1120px,calc(100% - 32px));margin:0 auto;padding:32px 0 56px;}"
                + ".hero{min-height:100vh;display:grid;align-items:center;grid-template-columns:1.1fr .9fr;gap:20px;}"
                + ".panel{background:rgba(255,250,243,.92);border:1px solid var(--line);border-radius:24px;padding:24px;box-shadow:0 18px 60px rgba(64,44,18,.08);backdrop-filter:blur(8px);}"
                + ".auth-panel{max-width:520px;}.side-panel{align-self:center;}"
                + ".grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:20px;width:min(1120px,calc(100% - 32px));margin:0 auto 56px;}"
                + ".admin-grid{grid-template-columns:repeat(2,minmax(0,1fr));}"
                + ".wide{grid-column:1 / -1;}.stat strong{display:block;font-size:2.5rem;margin-top:8px;}"
                + ".app-header{width:min(1120px,calc(100% - 32px));margin:0 auto;padding:32px 0 20px;display:flex;justify-content:space-between;gap:16px;align-items:flex-start;}"
                + ".eyebrow{display:inline-block;font-size:.78rem;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);margin-bottom:10px;}"
                + "h1,h2{margin:0 0 10px;font-family:Georgia,Times New Roman,serif;}h1{font-size:clamp(2.2rem,4vw,4rem);line-height:1.05;}h2{font-size:1.4rem;}p{margin:0 0 14px;line-height:1.5;color:var(--muted);}"
                + ".stack{display:grid;gap:14px;margin-top:18px;}label{display:grid;gap:8px;font-weight:600;color:var(--ink);}input{width:100%;padding:14px 16px;border:1px solid var(--line);border-radius:14px;background:#fffdf9;font:inherit;}"
                + "button,.ghost-button{display:inline-flex;align-items:center;justify-content:center;padding:12px 18px;border-radius:999px;border:1px solid transparent;background:var(--accent);color:#fff;font-weight:700;cursor:pointer;text-decoration:none;transition:transform .15s ease,background .15s ease;}"
                + "button:hover,.ghost-button:hover{background:var(--accent-dark);transform:translateY(-1px);text-decoration:none;}"
                + ".ghost-button{background:transparent;border-color:var(--line);color:var(--ink);}"
                + ".status{padding:12px 14px;border-radius:14px;margin:12px 0 0;font-weight:600;}"
                + ".status.success{background:rgba(31,122,82,.1);color:var(--ok);border:1px solid rgba(31,122,82,.2);}"
                + ".status.error{background:rgba(159,47,47,.08);color:var(--error);border:1px solid rgba(159,47,47,.18);}"
                + ".muted{color:var(--muted);}ul{padding-left:20px;color:var(--muted);line-height:1.7;}"
                + "table{width:100%;border-collapse:collapse;margin-top:12px;}th,td{padding:14px 12px;border-top:1px solid var(--line);text-align:left;vertical-align:top;}th{font-size:.82rem;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);}code{font-family:Consolas,monospace;background:var(--soft);padding:2px 6px;border-radius:8px;}"
                + "@media (max-width:860px){.hero{grid-template-columns:1fr;padding:20px 0 36px;}.grid,.admin-grid{grid-template-columns:1fr;}.wide{grid-column:auto;}.app-header{flex-direction:column;}.auth-panel{max-width:none;}}"
                + "</style>"
                + "</head>"
                + "<body>"
                + (session == null ? body : "<main class=\"page\">" + body + "</main>")
                + "</body>"
                + "</html>";
    }

    private static String escape(String value) {
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
