// ============================================================
// AURORE INSTITUTS — WORKER CENTRAL
// Version corrigée / monofichier
// ============================================================

// ============================================================
// 1. ERREURS
// ============================================================

class AppError extends Error {
  constructor(status, code, message, details = undefined) {
    super(message);
    this.name = "AppError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

const Errors = {
  badRequest: (m = "Requête invalide.", d) =>
    new AppError(400, "BAD_REQUEST", m, d),

  unauthorized: (m = "Authentification requise.") =>
    new AppError(401, "UNAUTHORIZED", m),

  forbidden: (m = "Accès refusé.") =>
    new AppError(403, "FORBIDDEN", m),

  notFound: (m = "Ressource introuvable.") =>
    new AppError(404, "NOT_FOUND", m),

  conflict: (m = "Conflit sur la ressource.") =>
    new AppError(409, "CONFLICT", m),

  payloadTooLarge: (m = "Fichier ou requête trop volumineux.") =>
    new AppError(413, "PAYLOAD_TOO_LARGE", m),

  unsupportedMedia: (m = "Type de fichier non supporté.") =>
    new AppError(415, "UNSUPPORTED_MEDIA_TYPE", m),

  tooManyRequests: (m = "Trop de requêtes, réessayez plus tard.") =>
    new AppError(429, "TOO_MANY_REQUESTS", m),

  upstream: (m = "Service externe indisponible.", d) =>
    new AppError(502, "UPSTREAM_ERROR", m, d),

  internal: (m = "Erreur interne du serveur.", d) =>
    new AppError(500, "INTERNAL_ERROR", m, d),
};

// ============================================================
// 2. CONFIGURATION
// ============================================================

const ROLE_RANK = Object.freeze({
  public: 0,
  eleve: 1,
  parent: 1,
  professeur: 2,
  administration: 3,
  proviseur: 4,
  admin_general: 5,
});

const CONFIG = Object.freeze({
  cors: {
    defaultOrigin:
      "https://auroresectioninstituts.vercel.app",

    allowedMethods:
      "GET, POST, PUT, PATCH, DELETE, OPTIONS",

    allowedHeaders:
      "Authorization, Content-Type, Range, X-Filename, X-Category, X-Etablissement-Id, X-Classe-Id, X-Matiere-Id",

    exposeHeaders:
      "Content-Length, Content-Range, Accept-Ranges, ETag, Content-Type",

    maxAgeSeconds: 86400,
  },

  limits: {
    maxJsonBodyBytes: 256 * 1024,

    pagination: {
      defaultLimit: 20,
      maxLimit: 100,
    },

    rateLimit: {
      windowSeconds: 60,
      maxMutationsPerWindow: 30,
    },
  },

  uploads: {
    maxFileBytes: {
      image: 8 * 1024 * 1024,
      document: 30 * 1024 * 1024,
      video: 500 * 1024 * 1024,
      audio: 50 * 1024 * 1024,
      autre: 15 * 1024 * 1024,
    },

    allowed: {
      image: {
        extensions: [
          "jpg",
          "jpeg",
          "png",
          "webp",
          "gif",
        ],
        mimeTypes: [
          "image/jpeg",
          "image/png",
          "image/webp",
          "image/gif",
        ],
      },

      document: {
        extensions: [
          "pdf",
          "doc",
          "docx",
          "xls",
          "xlsx",
          "ppt",
          "pptx",
          "odt",
        ],

        mimeTypes: [
          "application/pdf",
          "application/msword",
          "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
          "application/vnd.ms-excel",
          "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
          "application/vnd.ms-powerpoint",
          "application/vnd.openxmlformats-officedocument.presentationml.presentation",
          "application/vnd.oasis.opendocument.text",
        ],
      },

      video: {
        extensions: [
          "mp4",
          "webm",
          "mov",
        ],

        mimeTypes: [
          "video/mp4",
          "video/webm",
          "video/quicktime",
        ],
      },

      audio: {
        extensions: [
          "mp3",
          "m4a",
          "ogg",
          "wav",
        ],

        mimeTypes: [
          "audio/mpeg",
          "audio/mp4",
          "audio/ogg",
          "audio/wav",
          "audio/x-wav",
        ],
      },

      autre: {
        extensions: [
          "txt",
          "csv",
        ],

        mimeTypes: [
          "text/plain",
          "text/csv",
        ],
      },
    },
  },
});

// ============================================================
// 3. CORS / RÉPONSES
// ============================================================

function resolveAllowedOrigin(request, env) {
  const origin = request.headers.get("Origin") || "";

  const extra = String(
    env?.ALLOWED_ORIGINS_EXTRA || ""
  )
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  const allowed = [
    CONFIG.cors.defaultOrigin,
    ...extra,
  ];

  return allowed.includes(origin)
    ? origin
    : null;
}

function corsHeaders(request, env) {
  const headers = {
    "Access-Control-Allow-Methods":
      CONFIG.cors.allowedMethods,

    "Access-Control-Allow-Headers":
      CONFIG.cors.allowedHeaders,

    "Access-Control-Expose-Headers":
      CONFIG.cors.exposeHeaders,

    "Access-Control-Max-Age":
      String(CONFIG.cors.maxAgeSeconds),

    Vary: "Origin",
  };

  const origin = resolveAllowedOrigin(
    request,
    env
  );

  if (origin) {
    headers["Access-Control-Allow-Origin"] =
      origin;
  }

  return headers;
}

function jsonResponse(
  data,
  {
    status = 200,
    headers = {},
    request,
    env,
  } = {}
) {
  return new Response(
    JSON.stringify(data),
    {
      status,

      headers: {
        "Content-Type":
          "application/json; charset=utf-8",

        ...(request
          ? corsHeaders(request, env)
          : {}),

        ...headers,
      },
    }
  );
}

function successResponse(
  data,
  {
    status = 200,
    meta,
    request,
    env,
  } = {}
) {
  const body = {
    ok: true,
    data,
  };

  if (meta !== undefined) {
    body.meta = meta;
  }

  return jsonResponse(body, {
    status,
    request,
    env,
  });
}

function errorResponse(
  err,
  {
    request,
    env,
    requestId,
  } = {}
) {
  const status =
    err?.status || 500;

  return jsonResponse(
    {
      ok: false,

      error: {
        code:
          err?.code ||
          "INTERNAL_ERROR",

        message:
          status >= 500
            ? "Une erreur interne est survenue."
            : err.message,

        requestId,
      },
    },
    {
      status,
      request,
      env,
    }
  );
}

// ============================================================
// 4. VALIDATION
// ============================================================

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function isUuid(value) {
  return (
    typeof value === "string" &&
    UUID_RE.test(value)
  );
}

function requireUuid(
  value,
  name = "id"
) {
  if (!isUuid(value)) {
    throw Errors.badRequest(
      `Le champ "${name}" doit être un UUID valide.`
    );
  }

  return value;
}

function parsePagination(searchParams) {
  let limit = Number.parseInt(
    searchParams.get("limit") ||
      CONFIG.limits.pagination.defaultLimit,
    10
  );

  let offset = Number.parseInt(
    searchParams.get("offset") || 0,
    10
  );

  if (
    !Number.isFinite(limit) ||
    limit < 1
  ) {
    limit =
      CONFIG.limits.pagination.defaultLimit;
  }

  if (
    limit >
    CONFIG.limits.pagination.maxLimit
  ) {
    limit =
      CONFIG.limits.pagination.maxLimit;
  }

  if (
    !Number.isFinite(offset) ||
    offset < 0
  ) {
    offset = 0;
  }

  return {
    limit,
    offset,
  };
}

function sanitizeFilename(raw = "fichier") {
  return String(raw)
    .replace(/[\\/]/g, "_")
    .replace(/[\u0000-\u001f]/g, "")
    .trim()
    .slice(0, 150) || "fichier";
}

function getExtension(name) {
  const match =
    /\.([a-z0-9]+)$/i.exec(
      name || ""
    );

  return match
    ? match[1].toLowerCase()
    : "";
}

function getUploadRules(category) {
  return (
    CONFIG.uploads.allowed[category] ||
    null
  );
}

function getMaxBytes(category) {
  return (
    CONFIG.uploads.maxFileBytes[
      category
    ] ??
    CONFIG.uploads.maxFileBytes.autre
  );
}

function validateUpload({
  category,
  filename,
  mimeType,
  sizeBytes,
}) {
  const rules =
    getUploadRules(category);

  if (!rules) {
    throw Errors.badRequest(
      `Catégorie inconnue : "${category}".`
    );
  }

  const extension =
    getExtension(filename);

  if (
    !rules.extensions.includes(
      extension
    )
  ) {
    throw Errors.unsupportedMedia(
      `Extension .${extension || "?"} non autorisée.`
    );
  }

  if (
    !rules.mimeTypes.includes(
      mimeType
    )
  ) {
    throw Errors.unsupportedMedia(
      `Type MIME "${mimeType}" non autorisé.`
    );
  }

  if (
    typeof sizeBytes === "number" &&
    sizeBytes >
      getMaxBytes(category)
  ) {
    throw Errors.payloadTooLarge(
      `Fichier trop volumineux pour ${category}.`
    );
  }
}

function pickWritableFields(
  body,
  fields
) {
  const output = {};

  for (const field of fields) {
    if (
      Object.prototype.hasOwnProperty.call(
        body,
        field
      )
    ) {
      output[field] = body[field];
    }
  }

  return output;
}

function assertJsonBodySize(text) {
  const bytes =
    new TextEncoder().encode(
      text || ""
    ).length;

  if (
    bytes >
    CONFIG.limits.maxJsonBodyBytes
  ) {
    throw Errors.payloadTooLarge(
      "Corps JSON trop volumineux."
    );
  }
}

// ============================================================
// 5. SUPABASE
// ============================================================

function supabaseHeaders(
  env,
  {
    service = false,
    jwt = null,
    prefer,
  } = {}
) {
  const key = service
    ? env.SUPABASE_SERVICE_ROLE_KEY
    : env.SUPABASE_ANON_KEY;

  if (!key) {
    throw Errors.internal(
      service
        ? "Secret Supabase service manquant."
        : "Clé Supabase publique manquante."
    );
  }

  const headers = {
    apikey: key,

    Authorization: `Bearer ${
      service
        ? key
        : jwt || key
    }`,

    "Content-Type":
      "application/json",
  };

  if (prefer) {
    headers.Prefer = prefer;
  }

  return headers;
}

async function supabaseRequest(
  env,
  {
    method = "GET",
    table,
    query = "",
    body,
    service = false,
    jwt = null,
    prefer,
  } = {}
) {
  const url =
    `${env.SUPABASE_URL}/rest/v1/${table}` +
    (query ? `?${query}` : "");

  const response =
    await fetch(url, {
      method,

      headers:
        supabaseHeaders(env, {
          service,
          jwt,
          prefer,
        }),

      body:
        body === undefined
          ? undefined
          : JSON.stringify(body),
    });

  if (!response.ok) {
    let details;

    try {
      details =
        await response.json();
    } catch {
      details =
        await response.text()
          .catch(() => undefined);
    }

    if (
      response.status === 401 ||
      response.status === 403
    ) {
      throw Errors.forbidden(
        "Accès refusé par Supabase."
      );
    }

    throw Errors.upstream(
      `Erreur Supabase (${response.status}).`,
      details
    );
  }

  if (response.status === 204) {
    return null;
  }

  const text =
    await response.text();

  return text
    ? JSON.parse(text)
    : null;
}

function makeSupabaseClient(
  env,
  { userJwt = null } = {}
) {
  return {
    asUser: {
      select: (table, query) =>
        supabaseRequest(env, {
          table,
          query,
          jwt: userJwt,
        }),

      insert: (
        table,
        body,
        options = {}
      ) =>
        supabaseRequest(env, {
          method: "POST",
          table,
          body,
          jwt: userJwt,
          prefer:
            `return=${
              options.returning ||
              "representation"
            }`,
        }),

      update: (
        table,
        query,
        body,
        options = {}
      ) =>
        supabaseRequest(env, {
          method: "PATCH",
          table,
          query,
          body,
          jwt: userJwt,
          prefer:
            `return=${
              options.returning ||
              "representation"
            }`,
        }),

      delete: (
        table,
        query
      ) =>
        supabaseRequest(env, {
          method: "DELETE",
          table,
          query,
          jwt: userJwt,
        }),
    },

    asService: {
      select: (table, query) =>
        supabaseRequest(env, {
          table,
          query,
          service: true,
        }),

      insert: (
        table,
        body,
        options = {}
      ) =>
        supabaseRequest(env, {
          method: "POST",
          table,
          body,
          service: true,
          prefer:
            `return=${
              options.returning ||
              "representation"
            }`,
        }),

      update: (
        table,
        query,
        body,
        options = {}
      ) =>
        supabaseRequest(env, {
          method: "PATCH",
          table,
          query,
          body,
          service: true,
          prefer:
            `return=${
              options.returning ||
              "representation"
            }`,
        }),

      delete: (
        table,
        query
      ) =>
        supabaseRequest(env, {
          method: "DELETE",
          table,
          query,
          service: true,
        }),
    },
  };
}

// ============================================================
// 6. AUTHENTIFICATION
// ============================================================

function extractBearerToken(
  request
) {
  const header =
    request.headers.get(
      "Authorization"
    ) || "";

  const match =
    header.match(
      /^Bearer\s+(.+)$/i
    );

  return match
    ? match[1].trim()
    : null;
}

async function authUser(
  env,
  token
) {
  const response =
    await fetch(
      `${env.SUPABASE_URL}/auth/v1/user`,
      {
        headers: {
          apikey:
            env.SUPABASE_ANON_KEY,

          Authorization:
            `Bearer ${token}`,
        },
      }
    );

  if (
    response.status === 401 ||
    response.status === 403
  ) {
    return null;
  }

  if (!response.ok) {
    throw Errors.upstream(
      "Impossible de vérifier la session Supabase Auth."
    );
  }

  return response.json();
}

function normalizeMemberRole(
  role
) {
  const value =
    String(role || "")
      .toLowerCase()
      .trim();

  const map = {
    admin: "administration",
    administrateur:
      "administration",
    administration:
      "administration",

    professeur:
      "professeur",

    enseignant:
      "professeur",

    teacher:
      "professeur",

    proviseur:
      "proviseur",

    directeur:
      "proviseur",

    direction:
      "proviseur",
  };

  return map[value] || null;
}

async function resolveIdentity(
  request,
  env
) {
  const token =
    extractBearerToken(request);

  if (!token) {
    return {
      user: null,
      role: "public",
      etablissementId: null,
      userJwt: null,
    };
  }

  const user =
    await authUser(
      env,
      token
    );

  if (!user?.id) {
    throw Errors.unauthorized(
      "Session invalide ou expirée."
    );
  }

  const configuredAdmins =
    new Set(
      String(
        env.ADMIN_GENERAL_USER_IDS ||
          ""
      )
        .split(",")
        .map((value) =>
          value.trim()
        )
        .filter(Boolean)
    );

  if (
    configuredAdmins.has(user.id)
  ) {
    return {
      user,
      role: "admin_general",
      etablissementId: null,
      userJwt: token,
    };
  }

  const supabase =
    makeSupabaseClient(env);

  const members =
    await supabase.asUser.select(
      "etablissement_membres",
      [
        `profile_id=eq.${encodeURIComponent(
          user.id
        )}`,

        "select=id,etablissement_id,profile_id,role",

        "limit=20",
      ].join("&")
    );

  if (!members?.length) {
    throw Errors.forbidden(
      "Votre compte n'est associé à aucun espace autorisé."
    );
  }

  const normalized =
    members
      .map((member) => ({
        ...member,
        normalizedRole:
          normalizeMemberRole(
            member.role
          ),
      }))
      .filter(
        (member) =>
          member.normalizedRole
      );

  if (!normalized.length) {
    throw Errors.forbidden(
      "Aucun rôle autorisé n'a été trouvé pour ce compte."
    );
  }

  normalized.sort(
    (a, b) =>
      ROLE_RANK[
        b.normalizedRole
      ] -
      ROLE_RANK[
        a.normalizedRole
      ]
  );

  const selected =
    normalized[0];

  return {
    user,
    role:
      selected.normalizedRole,
    etablissementId:
      selected.etablissement_id,
    userJwt: token,
  };
}

// ============================================================
// 7. AUTORISATIONS
// ============================================================

function requireAuthenticated(
  identity
) {
  if (!identity?.user) {
    throw Errors.unauthorized();
  }
}

function requireMinRole(
  identity,
  role
) {
  requireAuthenticated(
    identity
  );

  const current =
    ROLE_RANK[
      identity.role
    ] ?? 0;

  const required =
    ROLE_RANK[role] ?? 999;

  if (current < required) {
    throw Errors.forbidden();
  }
}

function requireSameEtablissement(
  identity,
  etablissementId
) {
  requireAuthenticated(
    identity
  );

  if (
    identity.role ===
    "admin_general"
  ) {
    return;
  }

  if (
    !identity.etablissementId ||
    identity.etablissementId !==
      etablissementId
  ) {
    throw Errors.forbidden(
      "Accès à cet établissement interdit."
    );
  }
}

function authorize(
  identity,
  allowedRoles,
  targetEtablissementId = null
) {
  requireAuthenticated(
    identity
  );

  const roles =
    Array.isArray(allowedRoles)
      ? allowedRoles
      : [];

  if (
    !roles.includes(
      identity.role
    )
  ) {
    throw Errors.forbidden();
  }

  if (
    targetEtablissementId
  ) {
    requireSameEtablissement(
      identity,
      targetEtablissementId
    );
  }
}

// ============================================================
// 8. REGISTRE DE RESSOURCES
// ============================================================
//
// Sécurité par défaut :
// - pas de lecture publique
// - aucune écriture publique
// - champs explicitement autorisés
//
// Pour ajouter plus tard une ressource :
// ajouter une entrée ici.
// ============================================================

const RESOURCES = Object.freeze({

  etablissements: {
    table: "etablissements",

    select: [
      "id",
      "nom",
      "slug",
      "type",
      "statut",
      "niveau",
      "domaine",
      "ville",
      "province",
      "adresse",
      "latitude",
      "longitude",
      "telephone",
      "email",
      "site_web",
      "annee_fondation",
      "logo_url",
      "cover_url",
      "presentation",
      "actif",
      "created_at",
      "updated_at",
    ],

    publicRead: true,

    publicFilter: {
      actif: true,
    },

    scopedBy:
      null,

    permissions: {
      read: [
        "public",
        "eleve",
        "parent",
        "professeur",
        "administration",
        "proviseur",
        "admin_general",
      ],

      create: [
        "admin_general",
      ],

      update: [
        "admin_general",
        "proviseur",
      ],

      delete: [
        "admin_general",
      ],
    },

    writable: [
      "nom",
      "slug",
      "type",
      "statut",
      "niveau",
      "domaine",
      "ville",
      "province",
      "adresse",
      "latitude",
      "longitude",
      "telephone",
      "email",
      "site_web",
      "annee_fondation",
      "logo_url",
      "cover_url",
      "presentation",
      "actif",
      "created_at",
      "updated_at",
    ],
  },
