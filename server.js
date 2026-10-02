require("dotenv").config();

const express = require("express");
const path = require("path");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const db = require("./database");

const app = express();


/* =========================================================
   CONFIG
========================================================= */

const PORT = Number(
    process.env.PORT || 3000
);

const JWT_SECRET =
    process.env.JWT_SECRET ||
    crypto
        .randomBytes(48)
        .toString("hex");

const ADMIN_USERNAME =
    process.env.ADMIN_USERNAME ||
    "nextaway";

const ADMIN_PASSWORD =
    process.env.ADMIN_PASSWORD ||
    "change-me";


/* =========================================================
   EXPRESS
========================================================= */

app.disable(
    "x-powered-by"
);

app.use(
    helmet({
        contentSecurityPolicy: false
    })
);

app.use(
    express.json({
        limit: "64kb"
    })
);


/* =========================================================
   RATE LIMIT LOGIN
========================================================= */

const loginLimiter =
    rateLimit({

        windowMs:
            15 *
            60 *
            1000,

        limit: 20,

        standardHeaders: true,

        legacyHeaders: false

    });


/* =========================================================
   PLANOS
========================================================= */

const PLAN_MS = {

    "1":
        24 *
        60 *
        60 *
        1000,

    "7":
        7 *
        24 *
        60 *
        60 *
        1000,

    "30":
        30 *
        24 *
        60 *
        60 *
        1000,

    lifetime:
        null

};


/* =========================================================
   AUTH ADMIN
========================================================= */

function adminAuth(
    req,
    res,
    next
) {

    const header =
        req.headers.authorization ||
        "";

    const token =
        header.startsWith(
            "Bearer "
        )
            ?
            header.slice(7)
            :
            "";


    try {

        req.admin =
            jwt.verify(
                token,
                JWT_SECRET
            );

        next();

    }
    catch {

        return res
            .status(401)
            .json({

                error:
                    "unauthorized"

            });

    }

}


/* =========================================================
   EXPIRAR KEYS VENCIDAS
========================================================= */

function expireOldKeys() {

    db.prepare(`
        UPDATE keys

        SET status = 'expired'

        WHERE
            status = 'active'

            AND expires_at IS NOT NULL

            AND expires_at <= ?
    `)
    .run(
        Date.now()
    );

}


/* =========================================================
   KEY FORMAT
========================================================= */

function generateKeyString() {

    const alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    const bytes =
        crypto.randomBytes(6);

    let suffix =
        "";


    for(
        let i = 0;
        i < 6;
        i++
    ) {

        suffix +=
            alphabet[
                bytes[i] %
                alphabet.length
            ];

    }


    return (
        "REMOTE-IOS-" +
        suffix
    );

}


/* =========================================================
   GERAR KEY ÚNICA
========================================================= */

function createUniqueKey(
    plan,
    durationMs,
    note
) {

    const statement =
        db.prepare(`
            INSERT OR IGNORE
            INTO keys (

                license_key,
                plan,
                duration_ms,
                status,
                created_at,
                note

            )

            VALUES (
                ?,
                ?,
                ?,
                'unused',
                ?,
                ?
            )
        `);


    for(
        let attempt = 0;
        attempt < 100;
        attempt++
    ) {

        const licenseKey =
            generateKeyString();


        const result =
            statement.run(

                licenseKey,

                plan,

                durationMs,

                Date.now(),

                note

            );


        /*
            INSERT OR IGNORE +
            UNIQUE no banco.

            Se por uma chance absurda
            a key já existir,
            changes será 0
            e outra será criada.
        */

        if(
            Number(
                result.changes
            ) === 1
        ) {

            return licenseKey;

        }

    }


    throw new Error(
        "Falha ao gerar uma key única."
    );

}


/* =========================================================
   LOGIN
========================================================= */

app.post(
    "/api/admin/login",
    loginLimiter,
    (
        req,
        res
    ) => {

        const username =
            String(
                req.body?.username ||
                ""
            );

        const password =
            String(
                req.body?.password ||
                ""
            );


        if(
            username !==
            ADMIN_USERNAME
            ||
            password !==
            ADMIN_PASSWORD
        ) {

            return res
                .status(401)
                .json({

                    error:
                        "invalid_credentials"

                });

        }


        const token =
            jwt.sign(

                {

                    sub:
                        ADMIN_USERNAME,

                    role:
                        "admin"

                },

                JWT_SECRET,

                {

                    expiresIn:
                        "12h"

                }

            );


        return res.json({

            ok:
                true,

            token,

            username:
                ADMIN_USERNAME

        });

    }
);


/* =========================================================
   ADMIN SESSION
========================================================= */

app.get(
    "/api/admin/me",
    adminAuth,
    (
        req,
        res
    ) => {

        return res.json({

            ok:
                true,

            username:
                req.admin.sub

        });

    }
);


/* =========================================================
   GERAR KEYS
========================================================= */

app.post(
    "/api/keys/generate",
    adminAuth,
    (
        req,
        res
    ) => {

        try {

            let {

                plan,

                customDays,

                quantity = 1,

                note = ""

            } =
                req.body ||
                {};


            plan =
                String(plan);


            quantity =
                Number(quantity);


            if(
                !Number.isFinite(
                    quantity
                )
            ) {

                quantity = 1;

            }


            quantity =
                Math.floor(
                    quantity
                );


            quantity =
                Math.max(
                    1,
                    Math.min(
                        100,
                        quantity
                    )
                );


            let durationMs;


            /* CUSTOM */

            if(
                plan ===
                "custom"
            ) {

                const days =
                    Number(
                        customDays
                    );


                if(
                    !Number.isFinite(
                        days
                    )
                    ||
                    days <= 0
                    ||
                    days > 100000
                ) {

                    return res
                        .status(400)
                        .json({

                            error:
                                "invalid_custom_days"

                        });

                }


                durationMs =
                    Math.round(
                        days *
                        86400000
                    );

            }


            /* PLANOS FIXOS */

            else if(

                Object.prototype
                    .hasOwnProperty
                    .call(
                        PLAN_MS,
                        plan
                    )

            ) {

                durationMs =
                    PLAN_MS[
                        plan
                    ];

            }


            else {

                return res
                    .status(400)
                    .json({

                        error:
                            "invalid_plan"

                    });

            }


            note =
                String(note)
                    .slice(
                        0,
                        200
                    );


            const generatedKeys =
                [];


            /* TRANSAÇÃO NODE:SQLITE */

            db.exec(
                "BEGIN IMMEDIATE;"
            );


            try {

                for(
                    let i = 0;
                    i < quantity;
                    i++
                ) {

                    generatedKeys.push(

                        createUniqueKey(

                            plan,

                            durationMs,

                            note

                        )

                    );

                }


                db.exec(
                    "COMMIT;"
                );

            }
            catch(
                error
            ) {

                try {

                    db.exec(
                        "ROLLBACK;"
                    );

                }
                catch {}


                throw error;

            }


            return res
                .status(201)
                .json({

                    ok:
                        true,

                    keys:
                        generatedKeys

                });

        }
        catch(
            error
        ) {

            console.error(
                "[GENERATE ERROR]",
                error
            );


            return res
                .status(500)
                .json({

                    error:
                        "generate_failed",

                    message:
                        error.message

                });

        }

    }
);


/* =========================================================
   LISTAR / BUSCAR KEYS
========================================================= */

app.get(
    "/api/keys",
    adminAuth,
    (
        req,
        res
    ) => {

        try {

            expireOldKeys();


            const search =
                String(
                    req.query.q ||
                    ""
                )
                .trim();


            const status =
                String(
                    req.query.status ||
                    ""
                )
                .trim();


            let sql =
                `
                SELECT *

                FROM keys

                WHERE 1 = 1
                `;


            const params =
                [];


            if(
                search
            ) {

                sql +=
                    `
                    AND license_key LIKE ?
                    `;


                params.push(
                    "%" +
                    search +
                    "%"
                );

            }


            if(
                status
            ) {

                sql +=
                    `
                    AND status = ?
                    `;


                params.push(
                    status
                );

            }


            sql +=
                `
                ORDER BY id DESC

                LIMIT 500
                `;


            const rows =
                db
                    .prepare(sql)
                    .all(
                        ...params
                    );


            return res.json({

                ok:
                    true,

                keys:
                    rows

            });

        }
        catch(
            error
        ) {

            console.error(
                "[LIST ERROR]",
                error
            );


            return res
                .status(500)
                .json({

                    error:
                        "list_failed"

                });

        }

    }
);


/* =========================================================
   CONSULTAR UMA KEY
========================================================= */

app.get(
    "/api/keys/:key",
    adminAuth,
    (
        req,
        res
    ) => {

        expireOldKeys();


        const row =
            db.prepare(`
                SELECT *

                FROM keys

                WHERE license_key = ?
            `)
            .get(
                req.params.key
            );


        if(
            !row
        ) {

            return res
                .status(404)
                .json({

                    error:
                        "not_found"

                });

        }


        return res.json({

            ok:
                true,

            key:
                row

        });

    }
);


/* =========================================================
   PAUSAR
========================================================= */

app.post(
    "/api/keys/:key/pause",
    adminAuth,
    (
        req,
        res
    ) => {

        expireOldKeys();


        const row =
            db.prepare(`
                SELECT *

                FROM keys

                WHERE license_key = ?
            `)
            .get(
                req.params.key
            );


        if(
            !row
        ) {

            return res
                .status(404)
                .json({

                    error:
                        "not_found"

                });

        }


        if(
            row.status !==
            "active"
        ) {

            return res
                .status(409)
                .json({

                    error:
                        "not_active"

                });

        }


        const now =
            Date.now();


        const remaining =
            row.expires_at
                ?
                Math.max(
                    0,
                    row.expires_at -
                    now
                )
                :
                null;


        db.prepare(`
            UPDATE keys

            SET
                status = 'paused',
                paused_at = ?,
                remaining_ms = ?,
                expires_at = NULL

            WHERE id = ?
        `)
        .run(
            now,
            remaining,
            row.id
        );


        return res.json({

            ok:
                true

        });

    }
);


/* =========================================================
   RETOMAR
========================================================= */

app.post(
    "/api/keys/:key/resume",
    adminAuth,
    (
        req,
        res
    ) => {

        const row =
            db.prepare(`
                SELECT *

                FROM keys

                WHERE license_key = ?
            `)
            .get(
                req.params.key
            );


        if(
            !row
        ) {

            return res
                .status(404)
                .json({

                    error:
                        "not_found"

                });

        }


        if(
            row.status !==
            "paused"
        ) {

            return res
                .status(409)
                .json({

                    error:
                        "not_paused"

                });

        }


        const now =
            Date.now();


        const expiresAt =
            row.remaining_ms ===
            null
            ||
            row.remaining_ms ===
            undefined

                ?

                null

                :

                now +
                Number(
                    row.remaining_ms
                );


        db.prepare(`
            UPDATE keys

            SET
                status = 'active',
                paused_at = NULL,
                remaining_ms = NULL,
                expires_at = ?

            WHERE id = ?
        `)
        .run(
            expiresAt,
            row.id
        );


        return res.json({

            ok:
                true

        });

    }
);


/* =========================================================
   RESET DEVICE
========================================================= */

app.post(
    "/api/keys/:key/reset-device",
    adminAuth,
    (
        req,
        res
    ) => {

        const result =
            db.prepare(`
                UPDATE keys

                SET device_token = NULL

                WHERE license_key = ?
            `)
            .run(
                req.params.key
            );


        if(
            Number(
                result.changes
            ) === 0
        ) {

            return res
                .status(404)
                .json({

                    error:
                        "not_found"

                });

        }


        return res.json({

            ok:
                true

        });

    }
);


/* =========================================================
   DESATIVAR
========================================================= */

app.post(
    "/api/keys/:key/disable",
    adminAuth,
    (
        req,
        res
    ) => {

        const result =
            db.prepare(`
                UPDATE keys

                SET status = 'disabled'

                WHERE license_key = ?
            `)
            .run(
                req.params.key
            );


        if(
            Number(
                result.changes
            ) === 0
        ) {

            return res
                .status(404)
                .json({

                    error:
                        "not_found"

                });

        }


        return res.json({

            ok:
                true

        });

    }
);


/* =========================================================
   REATIVAR
========================================================= */

app.post(
    "/api/keys/:key/enable",
    adminAuth,
    (
        req,
        res
    ) => {

        const row =
            db.prepare(`
                SELECT *

                FROM keys

                WHERE license_key = ?
            `)
            .get(
                req.params.key
            );


        if(
            !row
        ) {

            return res
                .status(404)
                .json({

                    error:
                        "not_found"

                });

        }


        let status =
            row.activated_at
                ?
                "active"
                :
                "unused";


        if(
            row.expires_at
            &&
            row.expires_at <=
            Date.now()
        ) {

            status =
                "expired";

        }


        db.prepare(`
            UPDATE keys

            SET status = ?

            WHERE id = ?
        `)
        .run(
            status,
            row.id
        );


        return res.json({

            ok:
                true

        });

    }
);


/* =========================================================
   EXCLUIR
========================================================= */

app.delete(
    "/api/keys/:key",
    adminAuth,
    (
        req,
        res
    ) => {

        const result =
            db.prepare(`
                DELETE FROM keys

                WHERE license_key = ?
            `)
            .run(
                req.params.key
            );


        if(
            Number(
                result.changes
            ) === 0
        ) {

            return res
                .status(404)
                .json({

                    error:
                        "not_found"

                });

        }


        return res.json({

            ok:
                true

        });

    }
);


/* =========================================================
   CLIENT ACTIVATE
========================================================= */

app.post(
    "/api/client/activate",
    (
        req,
        res
    ) => {

        expireOldKeys();


        const key =
            String(
                req.body?.key ||
                ""
            )
            .trim()
            .toUpperCase();


        const deviceToken =
            String(
                req.body?.device_token ||
                ""
            )
            .trim();


        if(
            !key ||
            !deviceToken
        ) {

            return res
                .status(400)
                .json({

                    error:
                        "missing_fields"

                });

        }


        if(
            deviceToken.length >
            256
        ) {

            return res
                .status(400)
                .json({

                    error:
                        "invalid_device_token"

                });

        }


        let row =
            db.prepare(`
                SELECT *

                FROM keys

                WHERE license_key = ?
            `)
            .get(
                key
            );


        if(
            !row
        ) {

            return res
                .status(404)
                .json({

                    error:
                        "invalid_key"

                });

        }


        if(
            row.status ===
            "disabled"
            ||
            row.status ===
            "expired"
            ||
            row.status ===
            "paused"
        ) {

            return res
                .status(403)
                .json({

                    error:
                        row.status

                });

        }


        if(
            row.device_token
            &&
            row.device_token !==
            deviceToken
        ) {

            return res
                .status(403)
                .json({

                    error:
                        "device_mismatch"

                });

        }


        const now =
            Date.now();


        /* PRIMEIRA ATIVAÇÃO */

        if(
            row.status ===
            "unused"
        ) {

            const expiresAt =
                row.duration_ms ===
                null
                ||
                row.duration_ms ===
                undefined

                    ?

                    null

                    :

                    now +
                    Number(
                        row.duration_ms
                    );


            db.prepare(`
                UPDATE keys

                SET
                    status = 'active',
                    device_token = ?,
                    activated_at = ?,
                    expires_at = ?,
                    last_seen_at = ?

                WHERE id = ?
            `)
            .run(

                deviceToken,

                now,

                expiresAt,

                now,

                row.id

            );

        }


        /* JÁ ATIVADA */

        else {

            db.prepare(`
                UPDATE keys

                SET
                    device_token =
                        COALESCE(
                            device_token,
                            ?
                        ),

                    last_seen_at = ?

                WHERE id = ?
            `)
            .run(

                deviceToken,

                now,

                row.id

            );

        }


        row =
            db.prepare(`
                SELECT *

                FROM keys

                WHERE id = ?
            `)
            .get(
                row.id
            );


        return res.json({

            ok:
                true,

            status:
                row.status,

            activated_at:
                row.activated_at,

            expires_at:
                row.expires_at,

            paused_at:
                row.paused_at,

            remaining_ms:
                row.remaining_ms

        });

    }
);


/* =========================================================
   HEALTH
========================================================= */

app.get(
    "/api/health",
    (
        req,
        res
    ) => {

        return res.json({

            ok:
                true,

            service:
                "rafaela",

            timestamp:
                Date.now()

        });

    }
);


/* =========================================================
   SITE
========================================================= */

app.use(
    express.static(
        path.join(
            __dirname,
            "public"
        )
    )
);


app.get(
    "*",
    (
        req,
        res
    ) => {

        res.sendFile(

            path.join(
                __dirname,
                "public",
                "index.html"
            )

        );

    }
);


/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
    (
        error,
        req,
        res,
        next
    ) => {

        console.error(
            "[SERVER ERROR]",
            error
        );


        return res
            .status(500)
            .json({

                error:
                    "internal_error"

            });

    }
);


/* =========================================================
   START
========================================================= */

app.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log(
            `RAFAELA on ${PORT}`
        );

    }
);