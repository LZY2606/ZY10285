package prism

import java.sql.Connection
import java.sql.DriverManager

/**
 * SQLite persistence with explicit, ordered migrations. The database file lives
 * next to the working directory (default ./prism.db); tests point it at a temp
 * file. No network, no external service.
 */
object Db {
    @Volatile
    private var conn: Connection? = null

    @Synchronized
    fun init(path: String) {
        conn?.close()
        val c = DriverManager.getConnection("jdbc:sqlite:$path")
        c.createStatement().use { st ->
            st.execute("PRAGMA journal_mode=WAL")
            st.execute("PRAGMA foreign_keys=ON")
        }
        conn = c
        migrate(c)
    }

    private fun migrate(c: Connection) {
        c.createStatement().use { st ->
            st.execute(
                """CREATE TABLE IF NOT EXISTS schema_migrations(
                     version INTEGER PRIMARY KEY,
                     applied_at TEXT NOT NULL DEFAULT (datetime('now'))
                   )"""
            )
        }
        val applied = mutableSetOf<Int>()
        c.createStatement().use { st ->
            val rs = st.executeQuery("SELECT version FROM schema_migrations")
            while (rs.next()) applied += rs.getInt(1)
        }
        val migrations = sortedMapOf<Int, String>(
            1 to """
                CREATE TABLE imports(
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  created_at TEXT NOT NULL DEFAULT (datetime('now')),
                  name TEXT,
                  mode TEXT NOT NULL,
                  input_hex TEXT NOT NULL,
                  canonical_hex TEXT,
                  report_json TEXT NOT NULL
                )
            """.trimIndent(),
            2 to "CREATE INDEX IF NOT EXISTS idx_imports_created ON imports(created_at DESC)",
        )
        for ((version, sql) in migrations) {
            if (version in applied) continue
            c.createStatement().use { st -> st.execute(sql) }
            c.prepareStatement("INSERT INTO schema_migrations(version) VALUES (?)").use { ps ->
                ps.setInt(1, version)
                ps.executeUpdate()
            }
        }
    }

    data class ImportRow(
        val id: Long, val createdAt: String, val name: String?,
        val mode: String, val inputHex: String, val canonicalHex: String?,
    )

    @Synchronized
    fun insertImport(name: String?, mode: Mode, inputHex: String, canonicalHex: String?, reportJson: String): Long {
        val c = conn ?: return -1
        c.prepareStatement(
            "INSERT INTO imports(name, mode, input_hex, canonical_hex, report_json) VALUES (?,?,?,?,?)"
        ).use { ps ->
            if (name == null) ps.setNull(1, java.sql.Types.VARCHAR) else ps.setString(1, name)
            ps.setString(2, mode.name)
            ps.setString(3, inputHex)
            if (canonicalHex == null) ps.setNull(4, java.sql.Types.VARCHAR) else ps.setString(4, canonicalHex)
            ps.setString(5, reportJson)
            ps.executeUpdate()
        }
        c.createStatement().use { st ->
            val rs = st.executeQuery("SELECT last_insert_rowid()")
            rs.next()
            return rs.getLong(1)
        }
    }

    @Synchronized
    fun listImports(limit: Int = 50): List<ImportRow> {
        val c = conn ?: return emptyList()
        c.prepareStatement(
            "SELECT id, created_at, name, mode, input_hex, canonical_hex FROM imports ORDER BY id DESC LIMIT ?"
        ).use { ps ->
            ps.setInt(1, limit)
            val rs = ps.executeQuery()
            val out = mutableListOf<ImportRow>()
            while (rs.next()) {
                out += ImportRow(
                    rs.getLong(1), rs.getString(2), rs.getString(3),
                    rs.getString(4), rs.getString(5), rs.getString(6),
                )
            }
            return out
        }
    }

    @Synchronized
    fun getReport(id: Long): String? {
        val c = conn ?: return null
        c.prepareStatement("SELECT report_json FROM imports WHERE id = ?").use { ps ->
            ps.setLong(1, id)
            val rs = ps.executeQuery()
            return if (rs.next()) rs.getString(1) else null
        }
    }

    @Synchronized
    fun close() {
        conn?.close()
        conn = null
    }
}
