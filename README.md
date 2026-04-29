# Local AI Chat

Localhost-only web app:

- Java backend on `127.0.0.1:8080`
- one HTML page with inline CSS and JS
- PostgreSQL on localhost
- Ollama on localhost
- encrypted PDF/TXT storage

## Run

1. Create the database:

```sql
CREATE DATABASE localai;
```

2. Run [schema.sql](/C:/Users/Chahat/Desktop/projects/Java-Project/schema.sql:1).

3. Set env vars if your local defaults differ:

```powershell
$env:LOCALAI_DB_URL="jdbc:postgresql://localhost:5432/localai"
$env:LOCALAI_DB_USER="postgres"
$env:LOCALAI_DB_PASSWORD="password"
$env:LOCALAI_OLLAMA_MODEL="mistral"
$env:LOCALAI_AES_KEY="replace-with-a-32-byte-secret"
$env:LOCALAI_PORT="8080"
```

4. Start Ollama, then run:

```powershell
mvn compile exec:java
```

5. Open:

```text
http://127.0.0.1:8080
```

## Notes

- First signup becomes the admin.
- Documents use AES-256-GCM at rest.
- Chat messages stay plaintext in PostgreSQL.
- Sessions are cookie-based and kept in memory because the app is localhost-only.
