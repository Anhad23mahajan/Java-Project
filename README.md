# VaultMind
VaultMind is a localhost-only Java web app prototype for a private document vault backed by PostgreSQL.

## Current scope
- run a local web server on `127.0.0.1`
- register and log in users through the browser
- keep separate admin and normal-user dashboards
- store file metadata in a vault database
- let signed-in users open decrypted versions of their own files
- let admins view users and stored file records

Decrypted file content is kept in memory only for the active session and is cleared on logout or session expiry.

The local AI document chat described in the problem statement is not implemented yet.

## Frontend templates
The UI is now rendered from HTML template files in `src/vaultmind/web/templates`.
Each page keeps its HTML, CSS, and any page-specific JavaScript inside a `.html` file instead of embedding frontend markup in Java source.

## PostgreSQL setup
Create a PostgreSQL database named `vaultmind`, then run the schema in `database/schema_postgresql.sql`.

The app reads these environment variables:
- `VAULTMIND_DB_URL` default: `jdbc:postgresql://localhost:5432/vaultmind`
- `VAULTMIND_DB_USER` default: `postgres`
- `VAULTMIND_DB_PASSWORD` default: `postgres`
- `VAULTMIND_PORT` default: `8080`
- `VAULTMIND_BOOTSTRAP_ADMIN` optional: `true` to create a local admin on startup
- `VAULTMIND_ADMIN_USERNAME` default when bootstrapping: `admin`
- `VAULTMIND_ADMIN_PASSWORD` required when bootstrapping an admin

## Run from terminal
1. Place the PostgreSQL JDBC jar at `lib/postgresql-42.7.5.jar`, or adjust the classpath to wherever you keep it.
2. Compile the project:

```powershell
javac -d out (Get-ChildItem -Recurse -Filter *.java | ForEach-Object { $_.FullName })
```

3. Run the main app:

```powershell
java -cp "out;lib\postgresql-42.7.5.jar" vaultmind.main.Main
```

4. Open the app in your browser:

```text
http://127.0.0.1:8080
```

## Optional admin bootstrap
To create an admin locally when the app starts:

```powershell
$env:VAULTMIND_BOOTSTRAP_ADMIN = "true"
$env:VAULTMIND_ADMIN_USERNAME = "admin"
$env:VAULTMIND_ADMIN_PASSWORD = "change-me"
java -cp "out;lib\postgresql-42.7.5.jar" vaultmind.main.Main
```

If you do not bootstrap an admin, registrations from the UI are created as normal users only.

## IntelliJ
Replace the old MySQL connector dependency with the PostgreSQL JDBC driver jar in project structure if IntelliJ still shows the previous library entry.
