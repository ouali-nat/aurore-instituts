/**
 * aurore-instituts-r2
 * ============================================================
 * Worker Cloudflare — passerelle sécurisée entre le frontend
 * Aurore Instituts (index.html) et le bucket R2 privé "aurore-instituts".
 *
 * ⚠️ Ce Worker est totalement indépendant du Worker "lsnb-pdf-worker-v2"
 *    (Aurore Archives). Ne pas fusionner, ne pas partager de code d'état.
 *
 * Variables d'environnement attendues :
 *  - R2_BUCKET
 *  - SUPABASE_URL
 *  - ALLOWED_ORIGINS
 *  - SUPABASE_JWT_SECRET
 *  - SUPABASE_SERVICE_ROLE_KEY
 */

const ROLES_UPLOAD_DELETE = ["owner", "admin", "teacher"];
const MAX_UPLOAD_BYTES = 512 * 1024 * 1024;

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const ALLOWED_MEDIA = new Set([
  "pdf",
  "video",
  "image",
  "audio",
  "autre",
]);

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const cors = buildCorsHeaders(origin, env);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: cors,
      });
    }

    const url = new URL(request.url);

    try {
      if (url.pathname === "/upload" && request.method === "POST") {
        return await handleUpload(request, env, cors);
      }

      if (url.pathname === "/file" && request.method === "GET") {
        return await handleGetFile(request, env, cors);
      }

      if (url.pathname === "/file" && request.method === "DELETE") {
        return await handleDeleteFile(request, env, cors);
      }

      return jsonResponse(
        { error: "Route inconnue" },
        404,
        cors
      );
    } catch (err) {
      return jsonResponse(
        {
          error: "Erreur interne",
          details: String((err && err.message) || err),
        },
        500,
        cors
      );
    }
  },
};

/* ============================================================
 * CORS
 * ============================================================ */

function buildCorsHeaders(origin, env) {
  const allowed = (env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((o) => o.trim())
    .filter(Boolean);

  const isVercelPreview =
    /^https:\/\/auroresectioninstituts(?:-[a-z0-9-]+)?\.vercel\.app$/i.test(
      origin
    );

  const isAllowed =
    allowed.includes(origin) || isVercelPreview;

  return {
    "Access-Control-Allow-Origin": isAllowed
      ? origin
      : "null",

    "Access-Control-Allow-Methods":
      "GET, POST, DELETE, OPTIONS",

    "Access-Control-Allow-Headers":
      "Content-Type, Authorization, Range",

    "Access-Control-Expose-Headers":
      "Content-Length, Content-Type, Content-Range, Accept-Ranges, ETag, Content-Disposition",

    "Access-Control-Max-Age": "86400",

    Vary: "Origin",
  };
}

function jsonResponse(data, status, cors) {
  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: {
        ...cors,
        "Content-Type":
          "application/json; charset=utf-8",
        "Cache-Control": "no-store",
      },
    }
  );
}

/* ============================================================
 * AUTHENTIFICATION — JWT Supabase HS256
 * ============================================================ */

async function getAuthenticatedUser(request, env) {
  const authHeader =
    request.headers.get("Authorization") || "";

  const match =
    authHeader.match(/^Bearer\s+(.+)$/i);

  if (!match) return null;

  const token = match[1];

  const payload = await verifySupabaseJwt(
    token,
    env.SUPABASE_JWT_SECRET
  );

  if (!payload || !payload.sub) {
    return null;
  }

  return {
    id: payload.sub,
    email: payload.email || null,
  };
}

async function verifySupabaseJwt(token, secret) {
  if (!secret) return null;

  const parts = token.split(".");

  if (parts.length !== 3) {
    return null;
  }

  const [
    headerB64,
    payloadB64,
    signatureB64,
  ] = parts;

  let header;

  try {
    header = JSON.parse(
      base64UrlDecode(headerB64)
    );
  } catch {
    return null;
  }

  if (header.alg !== "HS256") {
    return null;
  }

  const key =
    await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      {
        name: "HMAC",
        hash: "SHA-256",
      },
      false,
      ["verify"]
    );

  const signature =
    base64UrlDecodeToBytes(signatureB64);

  const valid =
    await crypto.subtle.verify(
      "HMAC",
      key,
      signature,
      new TextEncoder().encode(
        `${headerB64}.${payloadB64}`
      )
    );

  if (!valid) {
    return null;
  }

  let payload;

  try {
    payload = JSON.parse(
      base64UrlDecode(payloadB64)
    );
  } catch {
    return null;
  }

  if (
    payload.exp &&
    Date.now() / 1000 > payload.exp
  ) {
    return null;
  }

  return payload;
}

function base64UrlDecode(str) {
  return new TextDecoder().decode(
    base64UrlDecodeToBytes(str)
  );
}

function base64UrlDecodeToBytes(str) {
  const padded = str
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(
      str.length +
        ((4 - (str.length % 4)) % 4),
      "="
    );

  const binary = atob(padded);

  const bytes =
    new Uint8Array(binary.length);

  for (
    let i = 0;
    i < binary.length;
    i++
  ) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

/* ============================================================
 * AUTORISATION — rôle dans l'établissement
 * ============================================================ */

async function getUserRole(
  env,
  userId,
  etablissementId
) {
  if (!etablissementId) {
    return null;
  }

  const url =
    `${env.SUPABASE_URL}/rest/v1/etablissement_membres` +
    `?etablissement_id=eq.${encodeURIComponent(
      etablissementId
    )}` +
    `&profile_id=eq.${encodeURIComponent(
      userId
    )}` +
    `&select=role`;

  const res = await fetch(url, {
    headers: {
      apikey:
        env.SUPABASE_SERVICE_ROLE_KEY,

      Authorization:
        `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
    },
  });

  if (!res.ok) {
    return null;
  }

  const rows = await res.json();

  if (
    !Array.isArray(rows) ||
    rows.length === 0
  ) {
    return null;
  }

  return rows[0].role || null;
}

/* ============================================================
 * UPLOAD — POST /upload
 * ============================================================ */

async function handleUpload(
  request,
  env,
  cors
) {
  const user =
    await getAuthenticatedUser(
      request,
      env
    );

  if (!user) {
    return jsonResponse(
      { error: "Non authentifié" },
      401,
      cors
    );
  }

  const contentType =
    request.headers.get("Content-Type") || "";

  if (
    !contentType.includes(
      "multipart/form-data"
    )
  ) {
    return jsonResponse(
      {
        error:
          "Content-Type multipart/form-data attendu",
      },
      400,
      cors
    );
  }

  const form =
    await request.formData();

  const file = form.get("fichier");

  const etablissementId =
    form.get("etablissement_id");

  const classeId =
    form.get("classe_id") || null;

  const matiereId =
    form.get("matiere_id") || null;

  const typeMedia =
    form.get("type_media") || "autre";

  const filenameRaw =
    form.get("filename") ||
    (file && file.name) ||
    "fichier";

  if (!(file instanceof File)) {
    return jsonResponse(
      {
        error:
          "Champ 'fichier' manquant ou invalide",
      },
      400,
      cors
    );
  }

  if (!isUuid(etablissementId)) {
    return jsonResponse(
      {
        error:
          "etablissement_id invalide",
      },
      400,
      cors
    );
  }

  if (
    classeId &&
    !isUuid(classeId)
  ) {
    return jsonResponse(
      {
        error:
          "classe_id invalide",
      },
      400,
      cors
    );
  }

  if (
    matiereId &&
    !isUuid(matiereId)
  ) {
    return jsonResponse(
      {
        error:
          "matiere_id invalide",
      },
      400,
      cors
    );
  }

  if (
    !ALLOWED_MEDIA.has(
      String(typeMedia)
    )
  ) {
    return jsonResponse(
      {
        error:
          "type_media invalide",
      },
      400,
      cors
    );
  }

  if (
    file.size >
    MAX_UPLOAD_BYTES
  ) {
    return jsonResponse(
      {
        error:
          "Fichier trop volumineux",
      },
      413,
      cors
    );
  }

  const role =
    await getUserRole(
      env,
      user.id,
      etablissementId
    );

  if (
    !ROLES_UPLOAD_DELETE.includes(
      role
    )
  ) {
    return jsonResponse(
      {
        error:
          "Rôle insuffisant pour uploader dans cet établissement",
      },
      403,
      cors
    );
  }

  const key =
    buildObjectKey({
      etablissementId,
      classeId,
      matiereId,
      filename: filenameRaw,
    });

  await env.R2_BUCKET.put(
    key,
    file.stream(),
    {
      httpMetadata: {
        contentType:
          file.type ||
          "application/octet-stream",
      },
    }
  );

  return jsonResponse(
    {
      success: true,
      key,
      filename:
        sanitizeFilename(
          filenameRaw
        ),
      mime_type:
        file.type ||
        "application/octet-stream",
      size: file.size,
      type_media: typeMedia,
    },
    200,
    cors
  );
}

function buildObjectKey({
  etablissementId,
  classeId,
  matiereId,
  filename,
}) {
  const safeName =
    sanitizeFilename(filename);

  const uniqueId =
    crypto.randomUUID();

  const segments = [
    `etablissements/${etablissementId}`,
  ];

  if (classeId) {
    segments.push(
      `classes/${classeId}`
    );
  }

  if (matiereId) {
    segments.push(
      `matieres/${matiereId}`
    );
  }

  return `${segments.join("/")}/${uniqueId}-${safeName}`;
}

function sanitizeFilename(name) {
  const base = String(name)
    .normalize("NFKD")
    .replace(
      /[\u0300-\u036f]/g,
      ""
    );

  const cleaned = base
    .replace(
      /[^a-zA-Z0-9._-]/g,
      "_"
    )
    .replace(
      /_{2,}/g,
      "_"
    );

  return (
    cleaned.slice(0, 180) ||
    "fichier"
  );
}

/* ============================================================
 * RÉCUPÉRATION — GET /file?key=...
 * ============================================================ */

async function handleGetFile(
  request,
  env,
  cors
) {
  const url =
    new URL(request.url);

  const key =
    url.searchParams.get("key");

  if (
    !key ||
    !isSafeStorageKey(key)
  ) {
    return jsonResponse(
      {
        error:
          "Clé de fichier invalide",
      },
      400,
      cors
    );
  }

  const user =
    await getAuthenticatedUser(
      request,
      env
    );

  if (!user) {
    return jsonResponse(
      {
        error:
          "Non authentifié",
      },
      401,
      cors
    );
  }

  const etablissementId =
    extractEtablissementIdFromKey(
      key
    );

  const role =
    await getUserRole(
      env,
      user.id,
      etablissementId
    );

  if (!role) {
    return jsonResponse(
      {
        error:
          "Accès refusé à ce fichier",
      },
      403,
      cors
    );
  }

  const rangeHeader =
    request.headers.get("Range");

  const options = {};

  if (rangeHeader) {
    const r2Range =
      parseRangeHeader(
        rangeHeader
      );

    if (!r2Range) {
      return jsonResponse(
        {
          error:
            "Range invalide",
        },
        416,
        cors
      );
    }

    options.range = r2Range;
  }

  const object =
    await env.R2_BUCKET.get(
      key,
      options
    );

  if (!object) {
    return jsonResponse(
      {
        error:
          "Fichier introuvable",
      },
      404,
      cors
    );
  }

  const headers =
    new Headers(cors);

  object.writeHttpMetadata(
    headers
  );

  headers.set(
    "ETag",
    object.httpEtag
  );

  headers.set(
    "Accept-Ranges",
    "bytes"
  );

  if (object.range) {
    const {
      offset,
      length,
    } = object.range;

    headers.set(
      "Content-Range",
      `bytes ${offset}-${offset + length - 1}/${object.size}`
    );

    headers.set(
      "Content-Length",
      String(length)
    );

    return new Response(
      object.body,
      {
        status: 206,
        headers,
      }
    );
  }

  headers.set(
    "Content-Length",
    String(object.size)
  );

  return new Response(
    object.body,
    {
      status: 200,
      headers,
    }
  );
}

function parseRangeHeader(
  rangeHeader
) {
  const match =
    /^bytes=(\d*)-(\d*)$/.exec(
      String(rangeHeader).trim()
    );

  if (!match) {
    return null;
  }

  const [
    ,
    startStr,
    endStr,
  ] = match;

  if (
    startStr === "" &&
    endStr === ""
  ) {
    return null;
  }

  if (startStr === "") {
    const suffix =
      Number(endStr);

    if (
      !Number.isSafeInteger(
        suffix
      ) ||
      suffix <= 0
    ) {
      return null;
    }

    return { suffix };
  }

  const offset =
    Number(startStr);

  if (
    !Number.isSafeInteger(
      offset
    ) ||
    offset < 0
  ) {
    return null;
  }

  if (endStr === "") {
    return { offset };
  }

  const end =
    Number(endStr);

  if (
    !Number.isSafeInteger(
      end
    ) ||
    end < offset
  ) {
    return null;
  }

  return {
    offset,
    length:
      end - offset + 1,
  };
}

/* ============================================================
 * VALIDATION
 * ============================================================ */

function isUuid(value) {
  return UUID_RE.test(
    String(value || "")
  );
}

function isSafeStorageKey(key) {
  if (
    typeof key !== "string" ||
    key.length === 0 ||
    key.length > 1024
  ) {
    return false;
  }

  if (
    key.includes("..") ||
    key.startsWith("/") ||
    key.includes("\\")
  ) {
    return false;
  }

  const match =
    /^etablissements\/([^/]+)\/(.+)$/.exec(
      key
    );

  return Boolean(
    match &&
      isUuid(match[1]) &&
      match[2] &&
      !match[2].includes("..")
  );
}

function extractEtablissementIdFromKey(
  key
) {
  const match =
    /^etablissements\/([^/]+)\//.exec(
      key
    );

  return match &&
    isUuid(match[1])
    ? match[1]
    : null;
}

/* ============================================================
 * SUPPRESSION — DELETE /file?key=...
 * ============================================================ */

async function handleDeleteFile(
  request,
  env,
  cors
) {
  const url =
    new URL(request.url);

  const key =
    url.searchParams.get("key");

  if (
    !key ||
    !isSafeStorageKey(key)
  ) {
    return jsonResponse(
      {
        error:
          "Clé de fichier invalide",
      },
      400,
      cors
    );
  }

  const user =
    await getAuthenticatedUser(
      request,
      env
    );

  if (!user) {
    return jsonResponse(
      {
        error:
          "Non authentifié",
      },
      401,
      cors
    );
  }

  const etablissementId =
    extractEtablissementIdFromKey(
      key
    );

  const role =
    await getUserRole(
      env,
      user.id,
      etablissementId
    );

  if (
    !ROLES_UPLOAD_DELETE.includes(
      role
    )
  ) {
    return jsonResponse(
      {
        error:
          "Rôle insuffisant pour supprimer ce fichier",
      },
      403,
      cors
    );
  }

  await env.R2_BUCKET.delete(
    key
  );

  return jsonResponse(
    {
      success: true,
      key,
    },
    200,
    cors
  );
         }
