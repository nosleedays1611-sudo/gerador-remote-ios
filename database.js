const { DatabaseSync } = require("node:sqlite");
const path = require("path");
const fs = require("fs");


/* =========================================
   PASTA DO BANCO
========================================= */

const dataDir = path.join(
    __dirname,
    "data"
);

fs.mkdirSync(
    dataDir,
    {
        recursive: true
    }
);


/* =========================================
   ARQUIVO SQLITE
========================================= */

const databasePath = path.join(
    dataDir,
    "rafaela.db"
);


/* =========================================
   ABRIR BANCO
========================================= */

const db = new DatabaseSync(
    databasePath
);


/* =========================================
   CONFIGURAÇÕES
========================================= */

db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;
`);


/* =========================================
   TABELA DE KEYS
========================================= */

db.exec(`
    CREATE TABLE IF NOT EXISTS keys (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        license_key TEXT NOT NULL UNIQUE,

        plan TEXT NOT NULL,

        duration_ms INTEGER,

        status TEXT NOT NULL DEFAULT 'unused'
        CHECK (
            status IN (
                'unused',
                'active',
                'paused',
                'disabled',
                'expired'
            )
        ),

        device_token TEXT,

        created_at INTEGER NOT NULL,

        activated_at INTEGER,

        expires_at INTEGER,

        paused_at INTEGER,

        remaining_ms INTEGER,

        last_seen_at INTEGER,

        note TEXT NOT NULL DEFAULT ''

    );
`);


/* =========================================
   ÍNDICES
========================================= */

db.exec(`
    CREATE INDEX IF NOT EXISTS idx_keys_status
    ON keys(status);
`);


db.exec(`
    CREATE INDEX IF NOT EXISTS idx_keys_device
    ON keys(device_token);
`);


db.exec(`
    CREATE INDEX IF NOT EXISTS idx_keys_created
    ON keys(created_at);
`);


/* =========================================
   EXPORTAR BANCO
========================================= */

module.exports = db;