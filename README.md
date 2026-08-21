## VaultMind — Chat With Your Documents, Privately

A self-hosted web app for private document Q&A, built entirely on a local stack — no data ever leaves the machine it runs on.

### Why local-only

Most "chat with your documents" tools send your files to a cloud API. VaultMind doesn't: it runs a local LLM (TinyLlama, via Ollama) for the chat itself, stores documents encrypted at rest, and serves everything from a single localhost process — Java backend, PostgreSQL, and a one-page frontend with no external calls in the request path.

### What it does

- **Local LLM chat** — document Q&A powered by TinyLlama running through Ollama, with no cloud API dependency.
- **Context-injected retrieval** — chat responses are grounded by matching the query against stored documents before generating a reply.
- **Encrypted document storage** — PDF/TXT uploads are encrypted at rest with AES-256-GCM (12-byte IV) before hitting the database.
- **Real authentication** — BCrypt password hashing (cost factor 12), cookie-based sessions, first signup becomes admin.
- **Single-page frontend** — dark/light theme toggle, glassmorphism UI, no build step or frontend framework.

### Tech stack

**Backend:** Java, hand-rolled REST controller with polymorphic interfaces (`Database`, `EncryptionProvider`, `AiClient`, `AuthService`, `DataManager`) for clean separation of concerns
**Database:** PostgreSQL — 3 tables (users, documents with encrypted BYTEA content, chat messages)
**AI:** Ollama running TinyLlama, locally
**Security:** AES-256-GCM encryption, BCrypt hashing
**PDF/TXT parsing:** Apache PDFBox

### Running it locally

Create the database:

```sql
CREATE DATABASE localai;
```

Run `schema.sql` against it, then set environment variables if your local defaults differ:

```powershell
$env:VAULTMIND_DB_URL="jdbc:postgresql://localhost:5432/localai"
$env:VAULTMIND_DB_USER="postgres"
$env:VAULTMIND_DB_PASSWORD="password"
$env:VAULTMIND_OLLAMA_MODEL="mistral"
$env:VAULTMIND_AES_KEY="replace-with-a-32-byte-secret"
$env:VAULTMIND_PORT="8080"
```

Start Ollama, then:

```bash
mvn compile exec:java
```

Open `http://127.0.0.1:8080`.

### Notes

- First signup becomes the admin.
- Documents are encrypted with AES-256-GCM at rest; chat messages are stored as plaintext in PostgreSQL.
- Sessions are cookie-based and kept in memory — by design, since the app is localhost-only.
