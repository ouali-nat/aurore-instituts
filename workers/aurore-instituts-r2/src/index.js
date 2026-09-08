/**
 * Aurore Instituts — Cloudflare Worker
 * ------------------------------------
 * Ce Worker est totalement indépendant de l'infrastructure "Aurore Archives"
 * (lsnb-pdf-worker-v2, bucket lsnb-documents, ancien frontend, ancien Supabase).
 * Il ne touche à AUCUNE de ces ressources.
 *
 * Bindings / variables attendues (wrangler.toml + secrets) :
 *   - R2_BUCKET                  (binding R2)
 *   - SUPABASE_URL                (var)
 *   - SUPABASE_ANON_KEY            (var)
 *   - SUPABASE_SERVICE_ROLE_KEY    (secret)
 *   - ADMIN_GENERAL_USER_IDS       (secret, liste d'UUID séparés par des virgules)
 *   - ALLOWED_ORIGINS_EXTRA        (var, liste d'origines séparées par des virgules, optionnel)
 *
 * IMPORTANT — schéma réel utilisé (aucun champ imaginaire) :
 *   actualites(id, etablissement_id, titre, contenu, image_url, video_url, publie,
 *              published_at, created_at, updated_at)
 *   classes(id, etablissement_id, nom, niveau, annee_scolaire, actif, created_at)
 *   documents(id, etablissement_id, classe_id, matiere_id, titre, description,
 *             type_media, mime_type, fichier_url, miniature_url, taille_octets,
 *             duree_secondes, publie)
 *   eleves(id, etablissement_id, classe_id, profile_id, matricule, nom, prenom, created_at)
 *   etablissement_membres(id, etablissement_id, profile_id, role, created_at)
 *   etablissements(id, ...)
 *   evenements(id, etablissement_id, titre, description, lieu, debut, fin, image_url, created_at)
 *     -> PAS de colonne "publie" sur evenements.
 *   matieres(id, etablissement_id, nom, code, created_at)
 *   notifications(id, etablissement_id, profile_id, titre, message, lu, created_at)
 *   profiles(id, full_name, avatar_url, created_at)
 *     -> PAS de colonne "role" ni "etablissement_id" sur profiles.
 *   etablissement_galerie(id, etablissement_id, position, image_url, description,
 *                          actif, created_at, updated_at)
 *   site_support(id, cle, titre, description, telephone, email, whatsapp, horaires,
 *                actif, updated_at)
 *
 * NOTE SUR LE STOCKAGE R2 (point 10 du cahier des charges) :
 *   La table "documents" ne possède PAS de colonne "storage_key". Ce Worker ne
 *   crée donc PAS silencieusement une telle colonne : la clé de l'objet R2 est
 *   dérivée et stockée directement dans la colonne existante "fichier_url"
 *   (on y met la clé R2, ex. "etablissements/.../fichier.pdf"), et l'URL de
 *   téléchargement effective est reconstruite à la demande via
 *   GET /api/files/{key}. Une colonne "storage_key" dédiée serait plus propre
 *   à terme (à ajouter via migration Supabase si souhaité), mais ce n'est PAS
 *   supposé exister ici.
 *
 * NOTE SUR L'AUTHENTIFICATION :
 *   Conformément aux recommandations actuelles de Supabase, ce Worker NE
 *   vérifie PAS manuellement le JWT en HS256 avec le JWT secret. Il délègue
 *   la validation du token à l'endpoint officiel GET {SUPABASE_URL}/auth/v1/user
 *   (avec la clé anon + le Bearer token de l'utilisateur), ce qui reste valide
 *   quel que soit l'algorithme / le type de clé (HS256 legacy ou clés
 *   asymétriques ES256/RS256 nouvelle génération) configuré côté projet Supabase.
 *
 * NOTE SUR LES TYPES MIME AUTORISÉS :
 *   Le ZIP d'origine contenant la liste exacte des types autorisés n'a pas pu
 *   être récupéré. La liste ci-dessous (CATEGORY_MIME_TYPES) est une liste
 *   raisonnable par défaut à AJUSTER si votre liste d'origine diffère.
 *
 * NOTE PERFORMANCE (correctif 2026-09-08) :
 *   buildAuthContext() enchaînait auparavant 3 appels réseau Supabase l'un
 *   après l'autre (vérification du token, puis etablissement_membres, puis
 *   eleves) : chaque requête authentifiée du site attendait donc la somme des
 *   3 allers-retours. C'est la cause principale de la lenteur générale
 *   ressentie (accueil, "Mon espace", et surtout juste après la connexion
 *   Google puisque /api/me appelle immédiatement cette fonction). Les deux
 *   requêtes de lecture (etablissement_membres et eleves) ne dépendent pas
 *   l'une de l'autre : elles sont maintenant lancées en parallèle avec
 *   Promise.all, ce qui coupe ce temps d'environ un tiers à la moitié selon
 *   la latence réseau vers Supabase.
 */

// ---------------------------------------------------------------------------
// Constantes de configuration
// ---------------------------------------------------------------------------

const DEFAULT_FRONTEND_ORIGIN = 'https://auroresectioninstituts.vercel.app';

const VALID_ROLES = [
  'public',
  'eleve',
  'parent',
  'professeur',
  'administration',
  'proviseur',
  'admin_general',
];

const ROLE_NORMALIZATION_MAP = {
  admin: 'administration',
  administrateur: 'administration',
  administration: 'administration',
  professeur: 'professeur',
  enseignant: 'professeur',
  teacher: 'professeur',
  proviseur: 'proviseur',
  directeur: 'proviseur',
  direction: 'proviseur',
  parent: 'parent',
  eleve: 'eleve',
  eleve_: 'eleve',
  admin_general: 'admin_general',
};

// Rôles autorisés à créer/modifier/supprimer du contenu pédagogique
const STAFF_WRITE_ROLES = ['professeur', 'administration', 'proviseur', 'admin_general'];
// Rôles autorisés pour les opérations d'administration "lourdes"
const ADMIN_WRITE_ROLES = ['administration', 'proviseur', 'admin_general'];

const CATEGORY_SIZE_LIMITS_BYTES = {
  image: 8 * 1024 * 1024,
  document: 30 * 1024 * 1024,
  video: 500 * 1024 * 1024,
  audio: 50 * 1024 * 1024,
  autre: 15 * 1024 * 1024,
};

// Voir NOTE SUR LES TYPES MIME AUTORISÉS ci-dessus.
const CATEGORY_MIME_TYPES = {
  image: ['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'image/svg+xml'],
  document: [
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.ms-powerpoint',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'text/plain',
    'text/csv',
  ],
  video: ['video/mp4', 'video/webm', 'video/quicktime', 'video/x-msvideo'],
  audio: ['audio/mpeg', 'audio/mp3', 'audio/wav', 'audio/ogg', 'audio/webm'],
};

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const DEFAULT_PAGE_SIZE = 20;
const MAX_PAGE_SIZE = 100;

// Fenêtre de rate limiting simple, en mémoire (best effort, par isolate).
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_REQUESTS = 120;
const rateLimitStore = new Map();

// ---------------------------------------------------------------------------
// Utilitaires génériques
// ---------------------------------------------------------------------------

function isValidUUID(value) {
  return typeof value === 'string' && UUID_REGEX.test(value);
}

function normalizeRole(rawRole) {
  if (!rawRole) return null;
  const key = String(rawRole).trim().toLowerCase();
  return ROLE_NORMALIZATION_MAP[key] || null;
}

function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...extraHeaders,
    },
  });
}

function errorResponse(message, status = 400, code = 'BAD_REQUEST', extraHeaders = {}) {
  return jsonResponse({ error: { code, message } }, status, extraHeaders);
}

function getAllowedOrigins(env) {
  const extra = (env.ALLOWED_ORIGINS_EXTRA || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  return [DEFAULT_FRONTEND_ORIGIN, ...extra];
}

function buildCorsHeaders(request, env) {
  const origin = request.headers.get('Origin') || '';
  const allowedOrigins = getAllowedOrigins(env);
  const headers = {
    Vary: 'Origin',
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type, X-Requested-With, Range',
    'Access-Control-Expose-Headers': 'Content-Range, Accept-Ranges, Content-Length',
    'Access-Control-Max-Age': '86400',
  };
  if (allowedOrigins.includes(origin)) {
    headers['Access-Control-Allow-Origin'] = origin;
  } else if (allowedOrigins.length > 0) {
    // Origine non reconnue : pas de header ACAO -> le navigateur bloquera la requête.
  }
  return headers;
}

function withCors(response, corsHeaders) {
  const headers = new Headers(response.headers);
  for (const [key, value] of Object.entries(corsHeaders)) {
    headers.set(key, value);
  }
  return new Response(response.body, { status: response.status, headers });
}

function parsePagination(url) {
  let page = parseInt(url.searchParams.get('page') || '1', 10);
  let limit = parseInt(url.searchParams.get('limit') || String(DEFAULT_PAGE_SIZE), 10);
  if (!Number.isFinite(page) || page < 1) page = 1;
  if (!Number.isFinite(limit) || limit < 1) limit = DEFAULT_PAGE_SIZE;
  if (limit > MAX_PAGE_SIZE) limit = MAX_PAGE_SIZE;
  const from = (page - 1) * limit;
  const to = from + limit - 1;
  return { page, limit, from, to };
}

function checkRateLimit(request, env) {
  const key = request.headers.get('CF-Connecting-IP') || 'unknown';
  const now = Date.now();
  const entry = rateLimitStore.get(key);
  if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
    rateLimitStore.set(key, { windowStart: now, count: 1 });
    return true;
  }
  entry.count += 1;
  if (entry.count > RATE_LIMIT_MAX_REQUESTS) {
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Supabase — accès REST (service role, autorisation gérée par le Worker)
// ---------------------------------------------------------------------------

async function supabaseRest(env, path, { method = 'GET', body = null, headers = {}, prefer = null } = {}) {
  const url = `${env.SUPABASE_URL}/rest/v1/${path}`;
  const finalHeaders = {
    apikey: env.SUPABASE_SERVICE_ROLE_KEY,
    Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
    'Content-Type': 'application/json',
    ...headers,
  };
  if (prefer) finalHeaders['Prefer'] = prefer;
  const response = await fetch(url, {
    method,
    headers: finalHeaders,
    body: body !== null ? JSON.stringify(body) : undefined,
  });
  return response;
}

async function supabaseGetUser(env, accessToken) {
  if (!accessToken) return null;
  try {
    const response = await fetch(`${env.SUPABASE_URL}/auth/v1/user`, {
      headers: {
        apikey: env.SUPABASE_ANON_KEY,
        Authorization: `Bearer ${accessToken}`,
      },
    });
    if (!response.ok) return null;
    const user = await response.json();
    if (!user || !user.id) return null;
    return user;
  } catch (err) {
    return null;
  }
}

function extractBearerToken(request) {
  const header = request.headers.get('Authorization') || '';
  if (!header.startsWith('Bearer ')) return null;
  const token = header.slice('Bearer '.length).trim();
  return token || null;
}

/**
 * Construit le contexte d'authentification/autorisation de la requête :
 *   { user, isAdminGeneral, memberships: [{ etablissement_id, role }] }
 *
 * Correctif performance : les deux lectures (etablissement_membres et eleves)
 * sont indépendantes l'une de l'autre une fois l'utilisateur connu ; elles
 * partent donc en parallèle au lieu de s'enchaîner.
 */
async function buildAuthContext(request, env) {
  const token = extractBearerToken(request);
  const user = await supabaseGetUser(env, token);

  if (!user) {
    return { user: null, isAdminGeneral: false, memberships: [] };
  }

  const adminIds = (env.ADMIN_GENERAL_USER_IDS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const isAdminGeneral = adminIds.includes(user.id);

  const memberships = [];

  // Les deux lectures ci-dessous ne dépendent que de user.id : on les lance
  // en parallèle plutôt que l'une après l'autre (gain net de latence sur
  // CHAQUE requête authentifiée du site, y compris /api/me juste après la
  // connexion Google).
  const [membresResp, elevesResp] = await Promise.all([
    supabaseRest(
      env,
      `etablissement_membres?profile_id=eq.${encodeURIComponent(user.id)}&select=etablissement_id,role`
    ),
    supabaseRest(
      env,
      `eleves?profile_id=eq.${encodeURIComponent(user.id)}&select=etablissement_id`
    ),
  ]);

  // 1. Adhésions explicites via etablissement_membres
  if (membresResp.ok) {
    const rows = await membresResp.json();
    for (const row of rows) {
      const normalized = normalizeRole(row.role) || 'public';
      memberships.push({ etablissement_id: row.etablissement_id, role: normalized });
    }
  }

  // 2. Élèves reconnus via eleves.profile_id même sans ligne etablissement_membres
  if (elevesResp.ok) {
    const rows = await elevesResp.json();
    for (const row of rows) {
      const alreadyMember = memberships.some((m) => m.etablissement_id === row.etablissement_id);
      if (!alreadyMember) {
        memberships.push({ etablissement_id: row.etablissement_id, role: 'eleve' });
      }
    }
  }

  return { user, isAdminGeneral, memberships };
}

function getRoleForEtablissement(authCtx, etablissementId) {
  if (authCtx.isAdminGeneral) return 'admin_general';
  const membership = authCtx.memberships.find((m) => m.etablissement_id === etablissementId);
  return membership ? membership.role : null;
}

function hasAccessToEtablissement(authCtx, etablissementId) {
  if (authCtx.isAdminGeneral) return true;
  return authCtx.memberships.some((m) => m.etablissement_id === etablissementId);
}

function roleAllowed(role, allowedRoles) {
  if (!role) return false;
  return allowedRoles.includes(role);
}

// ---------------------------------------------------------------------------
// R2 — gestion des fichiers
// ---------------------------------------------------------------------------

function detectCategoryFromMime(mimeType) {
  for (const [category, mimes] of Object.entries(CATEGORY_MIME_TYPES)) {
    if (mimes.includes(mimeType)) return category;
  }
  return 'autre';
}

function isMimeTypeAllowed(mimeType, category) {
  if (category === 'autre') return true;
  const allowed = CATEGORY_MIME_TYPES[category] || [];
  return allowed.includes(mimeType);
}

function sanitizeFilename(filename) {
  const cleaned = String(filename || 'fichier')
    .normalize('NFKD')
    .replace(/[^a-zA-Z0-9._-]/g, '_')
    .replace(/_+/g, '_');
  return cleaned.slice(-150) || 'fichier';
}

function buildObjectKey(etablissementId, category, filename) {
  const year = new Date().getFullYear();
  const uuid = crypto.randomUUID();
  const safeName = sanitizeFilename(filename);
  return `etablissements/${etablissementId}/${category}/${year}/${uuid}-${safeName}`;
}

function isValidObjectKeyForEtablissement(key, etablissementId) {
  if (typeof key !== 'string' || key.length === 0) return false;
  const prefix = `etablissements/${etablissementId}/`;
  return key.startsWith(prefix) && !key.includes('..');
}

function parseRangeHeader(rangeHeader, size) {
  if (!rangeHeader || !rangeHeader.startsWith('bytes=')) return null;
  const [startStr, endStr] = rangeHeader.replace('bytes=', '').split('-');
  let start = startStr ? parseInt(startStr, 10) : 0;
  let end = endStr ? parseInt(endStr, 10) : size - 1;
  if (Number.isNaN(start)) start = 0;
  if (Number.isNaN(end) || end >= size) end = size - 1;
  if (start > end || start < 0) return null;
  return { start, end };
}

// ---------------------------------------------------------------------------
// Handlers — santé
// ---------------------------------------------------------------------------

async function handleHealth() {
  return jsonResponse({ status: 'ok', service: 'aurore-instituts', time: new Date().toISOString() });
}

// ---------------------------------------------------------------------------
// Handlers — table générique (lecture/écriture avec isolation par établissement)
// ---------------------------------------------------------------------------

/**
 * Config des tables "simples" gérées de façon générique.
 * publicField : nom de la colonne booléenne qui, si true, autorise une lecture
 *               publique sans authentification (null si aucune telle colonne).
 */
const TABLE_CONFIG = {
  classes: {
    publicField: null,
    writeRoles: ADMIN_WRITE_ROLES,
  },
  matieres: {
    publicField: null,
    writeRoles: ADMIN_WRITE_ROLES,
  },
  actualites: {
    publicField: 'publie',
    writeRoles: ADMIN_WRITE_ROLES,
  },
  evenements: {
    // ATTENTION : evenements ne possède PAS de colonne "publie".
    publicField: null,
    writeRoles: ADMIN_WRITE_ROLES,
  },
  eleves: {
    publicField: null,
    writeRoles: ADMIN_WRITE_ROLES,
  },
  notifications: {
    publicField: null,
    writeRoles: ADMIN_WRITE_ROLES,
  },
  etablissement_galerie: {
    publicField: 'actif',
    writeRoles: ADMIN_WRITE_ROLES,
  },
};

async function handleGenericList(request, env, corsHeaders, tableName) {
  const config = TABLE_CONFIG[tableName];
  const url = new URL(request.url);
  const etablissementId = url.searchParams.get('etablissement_id');

  if (!etablissementId || !isValidUUID(etablissementId)) {
    return withCors(
      errorResponse('etablissement_id (UUID) est requis.', 400, 'INVALID_ETABLISSEMENT_ID'),
      corsHeaders
    );
  }

  const authCtx = await buildAuthContext(request, env);
  const hasAccess = hasAccessToEtablissement(authCtx, etablissementId);

  let queryParts = [`etablissement_id=eq.${encodeURIComponent(etablissementId)}`];

  if (!hasAccess) {
    if (config.publicField) {
      queryParts.push(`${config.publicField}=eq.true`);
    } else {
      return withCors(
        errorResponse('Accès non autorisé à cet établissement.', 403, 'FORBIDDEN'),
        corsHeaders
      );
    }
  }

  // Filtres additionnels simples supportés par certaines tables
  for (const field of ['classe_id', 'matiere_id', 'profile_id', 'actif']) {
    const value = url.searchParams.get(field);
    if (value !== null) {
      if ((field === 'classe_id' || field === 'matiere_id' || field === 'profile_id') && !isValidUUID(value)) {
        continue;
      }
      queryParts.push(`${field}=eq.${encodeURIComponent(value)}`);
    }
  }

  const { from, to } = parsePagination(url);
  const query = queryParts.join('&');
  const resp = await supabaseRest(env, `${tableName}?${query}&order=created_at.desc`, {
    headers: { Range: `${from}-${to}`, 'Range-Unit': 'items' },
    prefer: 'count=exact',
  });

  if (!resp.ok) {
    const errBody = await resp.text();
    return withCors(errorResponse(`Erreur Supabase: ${errBody}`, 502, 'SUPABASE_ERROR'), corsHeaders);
  }

  const data = await resp.json();
  const contentRange = resp.headers.get('Content-Range');
  let total = null;
  if (contentRange && contentRange.includes('/')) {
    const totalStr = contentRange.split('/')[1];
    total = totalStr === '*' ? null : parseInt(totalStr, 10);
  }

  return withCors(jsonResponse({ data, pagination: { from, to, total } }), corsHeaders);
}

async function handleGenericCreate(request, env, corsHeaders, tableName) {
  const config = TABLE_CONFIG[tableName];
  let payload;
  try {
    payload = await request.json();
  } catch (err) {
    return withCors(errorResponse('Corps JSON invalide.', 400, 'INVALID_JSON'), corsHeaders);
  }

  const etablissementId = payload.etablissement_id;
  if (!etablissementId || !isValidUUID(etablissementId)) {
    return withCors(
      errorResponse('etablissement_id (UUID) est requis dans le corps.', 400, 'INVALID_ETABLISSEMENT_ID'),
      corsHeaders
    );
  }

  const authCtx = await buildAuthContext(request, env);
  if (!authCtx.user) {
    return withCors(errorResponse('Authentification requise.', 401, 'UNAUTHENTICATED'), corsHeaders);
  }
  const role = getRoleForEtablissement(authCtx, etablissementId);
  if (!roleAllowed(role, config.writeRoles)) {
    return withCors(errorResponse('Rôle insuffisant pour cette opération.', 403, 'FORBIDDEN'), corsHeaders);
  }

  const resp = await supabaseRest(env, tableName, {
    method: 'POST',
    body: payload,
    prefer: 'return=representation',
  });

  if (!resp.ok) {
    const errBody = await resp.text();
    return withCors(errorResponse(`Erreur Supabase: ${errBody}`, 502, 'SUPABASE_ERROR'), corsHeaders);
  }

  const created = await resp.json();
  return withCors(jsonResponse({ data: created[0] || created }, 201), corsHeaders);
}

async function handleGenericUpdate(request, env, corsHeaders, tableName, recordId) {
  const config = TABLE_CONFIG[tableName];
  if (!isValidUUID(recordId)) {
    return withCors(errorResponse('Identifiant invalide.', 400, 'INVALID_ID'), corsHeaders);
  }

  let payload;
  try {
    payload = await request.json();
  } catch (err) {
    return withCors(errorResponse('Corps JSON invalide.', 400, 'INVALID_JSON'), corsHeaders);
  }

  // On récupère la ligne existante pour connaître son etablissement_id réel
  const existingResp = await supabaseRest(
    env,
    `${tableName}?id=eq.${encodeURIComponent(recordId)}&select=etablissement_id`
  );
  if (!existingResp.ok) {
    return withCors(errorResponse('Erreur lors de la vérification.', 502, 'SUPABASE_ERROR'), corsHeaders);
  }
  const existingRows = await existingResp.json();
  if (existingRows.length === 0) {
    return withCors(errorResponse('Ressource introuvable.', 404, 'NOT_FOUND'), corsHeaders);
  }
  const etablissementId = existingRows[0].etablissement_id;

  const authCtx = await buildAuthContext(request, env);
  if (!authCtx.user) {
    return withCors(errorResponse('Authentification requise.', 401, 'UNAUTHENTICATED'), corsHeaders);
  }
  const role = getRoleForEtablissement(authCtx, etablissementId);
  if (!roleAllowed(role, config.writeRoles)) {
    return withCors(errorResponse('Rôle insuffisant pour cette opération.', 403, 'FORBIDDEN'), corsHeaders);
  }

  // Empêche le déplacement d'une ressource vers un autre établissement
  delete payload.etablissement_id;
  delete payload.id;

  const resp = await supabaseRest(env, `${tableName}?id=eq.${encodeURIComponent(recordId)}`, {
    method: 'PATCH',
    body: payload,
    prefer: 'return=representation',
  });

  if (!resp.ok) {
    const errBody = await resp.text();
    return withCors(errorResponse(`Erreur Supabase: ${errBody}`, 502, 'SUPABASE_ERROR'), corsHeaders);
  }

  const updated = await resp.json();
  if (updated.length === 0) {
    return withCors(errorResponse('Ressource introuvable.', 404, 'NOT_FOUND'), corsHeaders);
  }

  return withCors(jsonResponse({ data: updated[0] }), corsHeaders);
}

async function handleGenericDelete(request, env, corsHeaders, tableName, recordId) {
  const config = TABLE_CONFIG[tableName];
  if (!isValidUUID(recordId)) {
    return withCors(errorResponse('Identifiant invalide.', 400, 'INVALID_ID'), corsHeaders);
  }

  const existingResp = await supabaseRest(
    env,
    `${tableName}?id=eq.${encodeURIComponent(recordId)}&select=etablissement_id`
  );
  if (!existingResp.ok) {
    return withCors(errorResponse('Erreur lors de la vérification.', 502, 'SUPABASE_ERROR'), corsHeaders);
  }
  const existingRows = await existingResp.json();
  if (existingRows.length === 0) {
    return withCors(errorResponse('Ressource introuvable.', 404, 'NOT_FOUND'), corsHeaders);
  }
  const etablissementId = existingRows[0].etablissement_id;

  const authCtx = await buildAuthContext(request, env);
  if (!authCtx.user) {
    return withCors(errorResponse('Authentification requise.', 401, 'UNAUTHENTICATED'), corsHeaders);
  }
  const role = getRoleForEtablissement(authCtx, etablissementId);
  if (!roleAllowed(role, config.writeRoles)) {
    return withCors(errorResponse('Rôle insuffisant pour cette opération.', 403, 'FORBIDDEN'), corsHeaders);
  }

  const resp = await supabaseRest(env, `${tableName}?id=eq.${encodeURIComponent(recordId)}`, {
    method: 'DELETE',
    prefer: 'return=minimal',
  });

  if (!resp.ok) {
    const errBody = await resp.text();
    return withCors(errorResponse(`Erreur Supabase: ${errBody}`, 502, 'SUPABASE_ERROR'), corsHeaders);
  }

  return withCors(jsonResponse({ data: { id: recordId, deleted: true } }), corsHeaders);
}

// ---------------------------------------------------------------------------
// Handlers — documents (métadonnées + intégration R2)
// ---------------------------------------------------------------------------

async function handleDocumentsList(request, env, corsHeaders) {
  const url = new URL(request.url);
  const etablissementId = url.searchParams.get('etablissement_id');
  if (!etablissementId || !isValidUUID(etablissementId)) {
    return withCors(
      errorResponse('etablissement_id (UUID) est requis.', 400, 'INVALID_ETABLISSEMENT_ID'),
      corsHeaders
    );
  }

  const authCtx = await buildAuthContext(request, env);
  const hasAccess = hasAccessToEtablissement(authCtx, etablissementId);

  let queryParts = [`etablissement_id=eq.${encodeURIComponent(etablissementId)}`];
  if (!hasAccess) {
    queryParts.push('publie=eq.true');
  }

  const classeId = url.searchParams.get('classe_id');
  if (classeId && isValidUUID(classeId)) {
    queryParts.push(`classe_id=eq.${encodeURIComponent(classeId)}`);
  }
  const matiereId = url.searchParams.get('matiere_id');
  if (matiereId && isValidUUID(matiereId)) {
    queryParts.push(`matiere_id=eq.${encodeURIComponent(matiereId)}`);
  }
  const typeMedia = url.searchParams.get('type_media');
  if (typeMedia) {
    queryParts.push(`type_media=eq.${encodeURIComponent(typeMedia)}`);
  }

  const { from, to } = parsePagination(url);
  const query = queryParts.join('&');
  const resp = await supabaseRest(env, `documents?${query}&order=id.desc`, {
    headers: { Range: `${from}-${to}`, 'Range-Unit': 'items' },
    prefer: 'count=exact',
  });

  if (!resp.ok) {
    const errBody = await resp.text();
    return withCors(errorResponse(`Erreur Supabase: ${errBody}`, 502, 'SUPABASE_ERROR'), corsHeaders);
  }

  const data = await resp.json();
  const contentRange = resp.headers.get('Content-Range');
  let total = null;
  if (contentRange && contentRange.includes('/')) {
    const totalStr = contentRange.split('/')[1];
    total = totalStr === '*' ? null : parseInt(totalStr, 10);
  }

  return withCors(jsonResponse({ data, pagination: { from, to, total } }), corsHeaders);
}

async function handleDocumentCreate(request, env, corsHeaders) {
  let payload;
  try {
    payload = await request.json();
  } catch (err) {
    return withCors(errorResponse('Corps JSON invalide.', 400, 'INVALID_JSON'), corsHeaders);
  }

  const etablissementId = payload.etablissement_id;
  if (!etablissementId || !isValidUUID(etablissementId)) {
    return withCors(
      errorResponse('etablissement_id (UUID) est requis dans le corps.', 400, 'INVALID_ETABLISSEMENT_ID'),
      corsHeaders
    );
  }

  const authCtx = await buildAuthContext(request, env);
  if (!authCtx.user) {
    return withCors(errorResponse('Authentification requise.', 401, 'UNAUTHENTICATED'), corsHeaders);
  }
  const role = getRoleForEtablissement(authCtx, etablissementId);
  if (!roleAllowed(role, STAFF_WRITE_ROLES)) {
    return withCors(errorResponse('Rôle insuffisant pour cette opération.', 403, 'FORBIDDEN'), corsHeaders);
  }

  if (!payload.fichier_url || !isValidObjectKeyForEtablissement(payload.fichier_url, etablissementId)) {
    return withCors(
      errorResponse(
        "fichier_url doit être une clé R2 valide obtenue via POST /api/upload.",
        400,
        'INVALID_FICHIER_URL'
      ),
      corsHeaders
    );
  }

  const resp = await supabaseRest(env, 'documents', {
    method: 'POST',
    body: payload,
    prefer: 'return=representation',
  });

  if (!resp.ok) {
    const errBody = await resp.text();
    return withCors(errorResponse(`Erreur Supabase: ${errBody}`, 502, 'SUPABASE_ERROR'), corsHeaders);
  }

  const created = await resp.json();
  return withCors(jsonResponse({ data: created[0] || created }, 201), corsHeaders);
}

async function handleDocumentUpdate(request, env, corsHeaders, documentId) {
  if (!isValidUUID(documentId)) {
    return withCors(errorResponse('Identifiant invalide.', 400, 'INVALID_ID'), corsHeaders);
  }

  let payload;
  try {
    payload = await request.json();
  } catch (err) {
    return withCors(errorResponse('Corps JSON invalide.', 400, 'INVALID_JSON'), corsHeaders);
  }

  const existingResp = await supabaseRest(
    env,
    `documents?id=eq.${encodeURIComponent(documentId)}&select=etablissement_id`
  );
  if (!existingResp.ok) {
    return withCors(errorResponse('Erreur lors de la vérification.', 502, 'SUPABASE_ERROR'), corsHeaders);
  }
  const existingRows = await existingResp.json();
  if (existingRows.length === 0) {
    return withCors(errorResponse('Document introuvable.', 404, 'NOT_FOUND'), corsHeaders);
  }
  const etablissementId = existingRows[0].etablissement_id;

  const authCtx = await buildAuthContext(request, env);
  if (!authCtx.user) {
    return withCors(errorResponse('Authentification requise.', 401, 'UNAUTHENTICATED'), corsHeaders);
  }
  const role = getRoleForEtablissement(authCtx, etablissementId);
  if (!roleAllowed(role, STAFF_WRITE_ROLES)) {
    return withCors(errorResponse('Rôle insuffisant pour cette opération.', 403, 'FORBIDDEN'), corsHeaders);
  }

  delete payload.etablissement_id;
  delete payload.id;
  if (payload.fichier_url && !isValidObjectKeyForEtablissement(payload.fichier_url, etablissementId)) {
    return withCors(errorResponse('fichier_url invalide pour cet établissement.', 400, 'INVALID_FICHIER_URL'), corsHeaders);
  }

  const resp = await supabaseRest(env, `documents?id=eq.${encodeURIComponent(documentId)}`, {
    method: 'PATCH',
    body: payload,
    prefer: 'return=representation',
  });

  if (!resp.ok) {
    const errBody = await resp.text();
    return withCors(errorResponse(`Erreur Supabase: ${errBody}`, 502, 'SUPABASE_ERROR'), corsHeaders);
  }

  const updated = await resp.json();
  return withCors(jsonResponse({ data: updated[0] }), corsHeaders);
}

async function handleDocumentDelete(request, env, corsHeaders, documentId) {
  if (!isValidUUID(documentId)) {
    return withCors(errorResponse('Identifiant invalide.', 400, 'INVALID_ID'), corsHeaders);
  }

  const existingResp = await supabaseRest(
    env,
    `documents?id=eq.${encodeURIComponent(documentId)}&select=etablissement_id,fichier_url`
  );
  if (!existingResp.ok) {
    return withCors(errorResponse('Erreur lors de la vérification.', 502, 'SUPABASE_ERROR'), corsHeaders);
  }
  const existingRows = await existingResp.json();
  if (existingRows.length === 0) {
    return withCors(errorResponse('Document introuvable.', 404, 'NOT_FOUND'), corsHeaders);
  }
  const { etablissement_id: etablissementId, fichier_url: objectKey } = existingRows[0];

  const authCtx = await buildAuthContext(request, env);
  if (!authCtx.user) {
    return withCors(errorResponse('Authentification requise.', 401, 'UNAUTHENTICATED'), corsHeaders);
  }
  const role = getRoleForEtablissement(authCtx, etablissementId);
  if (!roleAllowed(role, STAFF_WRITE_ROLES)) {
    return withCors(errorResponse('Rôle insuffisant pour cette opération.', 403, 'FORBIDDEN'), corsHeaders);
  }

  const dbResp = await supabaseRest(env, `documents?id=eq.${encodeURIComponent(documentId)}`, {
    method: 'DELETE',
    prefer: 'return=minimal',
  });

  if (!dbResp.ok) {
    const errBody = await dbResp.text();
    return withCors(errorResponse(`Erreur Supabase: ${errBody}`, 502, 'SUPABASE_ERROR'), corsHeaders);
  }

  if (objectKey && isValidObjectKeyForEtablissement(objectKey, etablissementId)) {
    try {
      await env.R2_BUCKET.delete(objectKey);
    } catch (err) {
      // La ligne DB est supprimée même si le fichier R2 échoue à être retiré ;
      // on le signale dans la réponse pour permettre un nettoyage manuel.
      return withCors(
        jsonResponse({
          data: { id: documentId, deleted: true, r2_warning: 'Échec de la suppression du fichier R2 associé.' },
        }),
        corsHeaders
      );
    }
  }

  return withCors(jsonResponse({ data: { id: documentId, deleted: true } }), corsHeaders);
}

// ---------------------------------------------------------------------------
// Handlers — upload / téléchargement / suppression de fichiers R2
// ---------------------------------------------------------------------------

async function handleUpload(request, env, corsHeaders) {
  const authCtx = await buildAuthContext(request, env);
  if (!authCtx.user) {
    return withCors(errorResponse('Authentification requise.', 401, 'UNAUTHENTICATED'), corsHeaders);
  }

  const url = new URL(request.url);
  const etablissementId = url.searchParams.get('etablissement_id');
  const filename = url.searchParams.get('filename');
  const declaredMimeType = request.headers.get('Content-Type') || 'application/octet-stream';

  if (!etablissementId || !isValidUUID(etablissementId)) {
    return withCors(errorResponse('etablissement_id (UUID) est requis.', 400, 'INVALID_ETABLISSEMENT_ID'), corsHeaders);
  }
  if (!filename) {
    return withCors(errorResponse('Le paramètre filename est requis.', 400, 'MISSING_FILENAME'), corsHeaders);
  }

  const role = getRoleForEtablissement(authCtx, etablissementId);
  if (!roleAllowed(role, STAFF_WRITE_ROLES)) {
    return withCors(errorResponse('Rôle insuffisant pour uploader un fichier.', 403, 'FORBIDDEN'), corsHeaders);
  }

  const category = detectCategoryFromMime(declaredMimeType);
  if (!isMimeTypeAllowed(declaredMimeType, category)) {
    return withCors(errorResponse(`Type de fichier non autorisé: ${declaredMimeType}`, 415, 'UNSUPPORTED_MEDIA_TYPE'), corsHeaders);
  }

  const contentLengthHeader = request.headers.get('Content-Length');
  const declaredSize = contentLengthHeader ? parseInt(contentLengthHeader, 10) : null;
  const sizeLimit = CATEGORY_SIZE_LIMITS_BYTES[category];
  if (declaredSize !== null && declaredSize > sizeLimit) {
    return withCors(
      errorResponse(`Fichier trop volumineux pour la catégorie "${category}" (limite: ${sizeLimit} octets).`, 413, 'FILE_TOO_LARGE'),
      corsHeaders
    );
  }
  if (!request.body) {
    return withCors(errorResponse('Corps de requête manquant.', 400, 'MISSING_BODY'), corsHeaders);
  }

  const objectKey = buildObjectKey(etablissementId, category, filename);

  try {
    await env.R2_BUCKET.put(objectKey, request.body, {
      httpMetadata: { contentType: declaredMimeType },
      customMetadata: {
        uploaded_by: authCtx.user.id,
        etablissement_id: etablissementId,
        original_filename: filename,
      },
    });
  } catch (err) {
    return withCors(errorResponse("Échec de l'upload vers R2.", 502, 'R2_UPLOAD_ERROR'), corsHeaders);
  }

  // Vérifie la taille réelle après upload si elle n'était pas connue à l'avance
  let actualSize = declaredSize;
  if (actualSize === null) {
    const head = await env.R2_BUCKET.head(objectKey);
    actualSize = head ? head.size : null;
    if (actualSize !== null && actualSize > sizeLimit) {
      await env.R2_BUCKET.delete(objectKey);
      return withCors(
        errorResponse(`Fichier trop volumineux pour la catégorie "${category}" (limite: ${sizeLimit} octets).`, 413, 'FILE_TOO_LARGE'),
        corsHeaders
      );
    }
  }

  return withCors(
    jsonResponse(
      {
        data: {
          object_key: objectKey,
          category,
          mime_type: declaredMimeType,
          size_bytes: actualSize,
        },
      },
      201
    ),
    corsHeaders
  );
}

function extractKeyFromPath(pathname, prefix) {
  // pathname ex: /api/files/etablissements/xxx/image/2026/uuid-nom.png
  const raw = pathname.slice(prefix.length);
  try {
    return decodeURIComponent(raw);
  } catch (err) {
    return raw;
  }
}

async function findDocumentByObjectKey(env, objectKey) {
  const resp = await supabaseRest(
    env,
    `documents?fichier_url=eq.${encodeURIComponent(objectKey)}&select=id,etablissement_id,publie,mime_type`
  );
  if (!resp.ok) return null;
  const rows = await resp.json();
  return rows[0] || null;
}

async function handleFileDownload(request, env, corsHeaders, objectKey) {
  if (!objectKey || objectKey.includes('..')) {
    return withCors(errorResponse('Clé de fichier invalide.', 400, 'INVALID_KEY'), corsHeaders);
  }

  const keyParts = objectKey.split('/');
  if (keyParts[0] !== 'etablissements' || !isValidUUID(keyParts[1] || '')) {
    return withCors(errorResponse('Clé de fichier invalide.', 400, 'INVALID_KEY'), corsHeaders);
  }
  const etablissementId = keyParts[1];

  const documentRow = await findDocumentByObjectKey(env, objectKey);
  const isPublicDocument = !!(documentRow && documentRow.publie === true);

  if (!isPublicDocument) {
    const authCtx = await buildAuthContext(request, env);
    if (!authCtx.user) {
      return withCors(errorResponse('Authentification requise.', 401, 'UNAUTHENTICATED'), corsHeaders);
    }
    if (!hasAccessToEtablissement(authCtx, etablissementId)) {
      return withCors(errorResponse('Accès non autorisé à ce fichier.', 403, 'FORBIDDEN'), corsHeaders);
    }
  }

  const object = await env.R2_BUCKET.get(objectKey, {
    range: request.headers.get('Range')
      ? undefined
      : undefined,
  });

  if (!object) {
    return withCors(errorResponse('Fichier introuvable.', 404, 'NOT_FOUND'), corsHeaders);
  }

  const size = object.size;
  const rangeHeader = request.headers.get('Range');
  const contentType = object.httpMetadata?.contentType || 'application/octet-stream';

  if (rangeHeader) {
    const range = parseRangeHeader(rangeHeader, size);
    if (!range) {
      return withCors(
        new Response(null, {
          status: 416,
          headers: { 'Content-Range': `bytes */${size}` },
        }),
        corsHeaders
      );
    }

    const ranged = await env.R2_BUCKET.get(objectKey, {
      range: { offset: range.start, length: range.end - range.start + 1 },
    });
    if (!ranged) {
      return withCors(errorResponse('Fichier introuvable.', 404, 'NOT_FOUND'), corsHeaders);
    }

    const headers = new Headers();
    headers.set('Content-Type', contentType);
    headers.set('Content-Range', `bytes ${range.start}-${range.end}/${size}`);
    headers.set('Accept-Ranges', 'bytes');
    headers.set('Content-Length', String(range.end - range.start + 1));

    return withCors(new Response(ranged.body, { status: 206, headers }), corsHeaders);
  }

  const headers = new Headers();
  headers.set('Content-Type', contentType);
  headers.set('Accept-Ranges', 'bytes');
  headers.set('Content-Length', String(size));

  return withCors(new Response(object.body, { status: 200, headers }), corsHeaders);
}

async function handleFileDelete(request, env, corsHeaders, objectKey) {
  if (!objectKey || objectKey.includes('..')) {
    return withCors(errorResponse('Clé de fichier invalide.', 400, 'INVALID_KEY'), corsHeaders);
  }
  const keyParts = objectKey.split('/');
  if (keyParts[0] !== 'etablissements' || !isValidUUID(keyParts[1] || '')) {
    return withCors(errorResponse('Clé de fichier invalide.', 400, 'INVALID_KEY'), corsHeaders);
  }
  const etablissementId = keyParts[1];

  const authCtx = await buildAuthContext(request, env);
  if (!authCtx.user) {
    return withCors(errorResponse('Authentification requise.', 401, 'UNAUTHENTICATED'), corsHeaders);
  }
  const role = getRoleForEtablissement(authCtx, etablissementId);
  if (!roleAllowed(role, STAFF_WRITE_ROLES)) {
    return withCors(errorResponse('Rôle insuffisant pour supprimer ce fichier.', 403, 'FORBIDDEN'), corsHeaders);
  }

  const documentRow = await findDocumentByObjectKey(env, objectKey);
  if (documentRow) {
    return withCors(
      errorResponse(
        'Ce fichier est référencé par un document. Supprimez le document (DELETE /api/documents/:id) plutôt que le fichier directement.',
        409,
        'FILE_REFERENCED'
      ),
      corsHeaders
    );
  }

  try {
    await env.R2_BUCKET.delete(objectKey);
  } catch (err) {
    return withCors(errorResponse('Échec de la suppression R2.', 502, 'R2_DELETE_ERROR'), corsHeaders);
  }

  return withCors(jsonResponse({ data: { object_key: objectKey, deleted: true } }), corsHeaders);
}

// ---------------------------------------------------------------------------
// Handlers — divers (etablissements, profiles, site_support, moi/rôles)
// ---------------------------------------------------------------------------

async function handleMe(request, env, corsHeaders) {
  const authCtx = await buildAuthContext(request, env);
  if (!authCtx.user) {
    return withCors(errorResponse('Authentification requise.', 401, 'UNAUTHENTICATED'), corsHeaders);
  }
  return withCors(
    jsonResponse({
      data: {
        id: authCtx.user.id,
        email: authCtx.user.email || null,
        is_admin_general: authCtx.isAdminGeneral,
        memberships: authCtx.memberships,
      },
    }),
    corsHeaders
  );
}

async function handleEtablissementsList(request, env, corsHeaders) {
  const authCtx = await buildAuthContext(request, env);

  if (authCtx.isAdminGeneral) {
    const url = new URL(request.url);
    const { from, to } = parsePagination(url);
    const resp = await supabaseRest(env, 'etablissements?select=*&order=id.desc', {
      headers: { Range: `${from}-${to}`, 'Range-Unit': 'items' },
      prefer: 'count=exact',
    });
    if (!resp.ok) {
      return withCors(errorResponse('Erreur Supabase.', 502, 'SUPABASE_ERROR'), corsHeaders);
    }
    const data = await resp.json();
    return withCors(jsonResponse({ data }), corsHeaders);
  }

  if (!authCtx.user || authCtx.memberships.length === 0) {
    return withCors(jsonResponse({ data: [] }), corsHeaders);
  }

  const ids = authCtx.memberships.map((m) => m.etablissement_id);
  const filter = ids.map((id) => encodeURIComponent(id)).join(',');
  const resp = await supabaseRest(env, `etablissements?id=in.(${filter})&select=*`);
  if (!resp.ok) {
    return withCors(errorResponse('Erreur Supabase.', 502, 'SUPABASE_ERROR'), corsHeaders);
  }
  const data = await resp.json();
  return withCors(jsonResponse({ data }), corsHeaders);
}

async function handleEtablissementGet(request, env, corsHeaders, etablissementId) {
  if (!isValidUUID(etablissementId)) {
    return withCors(errorResponse('Identifiant invalide.', 400, 'INVALID_ID'), corsHeaders);
  }
  const resp = await supabaseRest(env, `etablissements?id=eq.${encodeURIComponent(etablissementId)}&select=*`);
  if (!resp.ok) {
    return withCors(errorResponse('Erreur Supabase.', 502, 'SUPABASE_ERROR'), corsHeaders);
  }
  const rows = await resp.json();
  if (rows.length === 0) {
    return withCors(errorResponse('Établissement introuvable.', 404, 'NOT_FOUND'), corsHeaders);
  }
  // Fiche établissement considérée comme public (vitrine) : pas de restriction ici.
  return withCors(jsonResponse({ data: rows[0] }), corsHeaders);
}

async function handleProfileGet(request, env, corsHeaders, profileId) {
  if (!isValidUUID(profileId)) {
    return withCors(errorResponse('Identifiant invalide.', 400, 'INVALID_ID'), corsHeaders);
  }
  const authCtx = await buildAuthContext(request, env);
  if (!authCtx.user) {
    return withCors(errorResponse('Authentification requise.', 401, 'UNAUTHENTICATED'), corsHeaders);
  }

  const isSelf = authCtx.user.id === profileId;
  if (!isSelf && !authCtx.isAdminGeneral && authCtx.memberships.length === 0) {
    return withCors(errorResponse('Accès non autorisé.', 403, 'FORBIDDEN'), corsHeaders);
  }

  const resp = await supabaseRest(
    env,
    `profiles?id=eq.${encodeURIComponent(profileId)}&select=id,full_name,avatar_url,created_at`
  );
  if (!resp.ok) {
    return withCors(errorResponse('Erreur Supabase.', 502, 'SUPABASE_ERROR'), corsHeaders);
  }
  const rows = await resp.json();
  if (rows.length === 0) {
    return withCors(errorResponse('Profil introuvable.', 404, 'NOT_FOUND'), corsHeaders);
  }
  return withCors(jsonResponse({ data: rows[0] }), corsHeaders);
}

async function handleSiteSupportGet(request, env, corsHeaders) {
  const url = new URL(request.url);
  const cle = url.searchParams.get('cle');
  let query = 'actif=eq.true&select=cle,titre,description,telephone,email,whatsapp,horaires';
  if (cle) {
    query += `&cle=eq.${encodeURIComponent(cle)}`;
  }
  const resp = await supabaseRest(env, `site_support?${query}`);
  if (!resp.ok) {
    return withCors(errorResponse('Erreur Supabase.', 502, 'SUPABASE_ERROR'), corsHeaders);
  }
  const rows = await resp.json();
  return withCors(jsonResponse({ data: cle ? rows[0] || null : rows }), corsHeaders);
}

async function handleSiteSupportUpdate(request, env, corsHeaders, siteSupportId) {
  if (!isValidUUID(siteSupportId)) {
    return withCors(errorResponse('Identifiant invalide.', 400, 'INVALID_ID'), corsHeaders);
  }
  const authCtx = await buildAuthContext(request, env);
  if (!authCtx.user) {
    return withCors(errorResponse('Authentification requise.', 401, 'UNAUTHENTICATED'), corsHeaders);
  }
  if (!authCtx.isAdminGeneral) {
    return withCors(errorResponse('Réservé à admin_general.', 403, 'FORBIDDEN'), corsHeaders);
  }

  let payload;
  try {
    payload = await request.json();
  } catch (err) {
    return withCors(errorResponse('Corps JSON invalide.', 400, 'INVALID_JSON'), corsHeaders);
  }
  delete payload.id;

  const resp = await supabaseRest(env, `site_support?id=eq.${encodeURIComponent(siteSupportId)}`, {
    method: 'PATCH',
    body: payload,
    prefer: 'return=representation',
  });
  if (!resp.ok) {
    const errBody = await resp.text();
    return withCors(errorResponse(`Erreur Supabase: ${errBody}`, 502, 'SUPABASE_ERROR'), corsHeaders);
  }
  const updated = await resp.json();
  return withCors(jsonResponse({ data: updated[0] }), corsHeaders);
}

// ---------------------------------------------------------------------------
// Routeur principal
// ---------------------------------------------------------------------------

const SIMPLE_TABLES = new Set(Object.keys(TABLE_CONFIG));

async function router(request, env, corsHeaders) {
  const url = new URL(request.url);
  const { pathname } = url;
  const method = request.method.toUpperCase();

  // --- Santé ---
  if (pathname === '/health' || pathname === '/api/health') {
    return handleHealth();
  }

  // --- Moi / rôles ---
  if (pathname === '/api/me' && method === 'GET') {
    return handleMe(request, env, corsHeaders);
  }

  // --- Établissements ---
  if (pathname === '/api/etablissements' && method === 'GET') {
    return handleEtablissementsList(request, env, corsHeaders);
  }
  const etablissementMatch = pathname.match(/^\/api\/etablissements\/([^/]+)$/);
  if (etablissementMatch && method === 'GET') {
    return handleEtablissementGet(request, env, corsHeaders, etablissementMatch[1]);
  }

  // --- Profiles ---
  const profileMatch = pathname.match(/^\/api\/profiles\/([^/]+)$/);
  if (profileMatch && method === 'GET') {
    return handleProfileGet(request, env, corsHeaders, profileMatch[1]);
  }

  // --- Site support ---
  if (pathname === '/api/site_support' && method === 'GET') {
    return handleSiteSupportGet(request, env, corsHeaders);
  }
  const siteSupportMatch = pathname.match(/^\/api\/site_support\/([^/]+)$/);
  if (siteSupportMatch && method === 'PATCH') {
    return handleSiteSupportUpdate(request, env, corsHeaders, siteSupportMatch[1]);
  }

  // --- Documents (traitement spécifique) ---
  if (pathname === '/api/documents' && method === 'GET') {
    return handleDocumentsList(request, env, corsHeaders);
  }
  if (pathname === '/api/documents' && method === 'POST') {
    return handleDocumentCreate(request, env, corsHeaders);
  }
  const documentMatch = pathname.match(/^\/api\/documents\/([^/]+)$/);
  if (documentMatch && (method === 'PATCH' || method === 'PUT')) {
    return handleDocumentUpdate(request, env, corsHeaders, documentMatch[1]);
  }
  if (documentMatch && method === 'DELETE') {
    return handleDocumentDelete(request, env, corsHeaders, documentMatch[1]);
  }

  // --- Upload / fichiers R2 ---
  if (pathname === '/api/upload' && method === 'POST') {
    return handleUpload(request, env, corsHeaders);
  }
  const FILES_PREFIX = '/api/files/';
  if (pathname.startsWith(FILES_PREFIX) && method === 'GET') {
    const key = extractKeyFromPath(pathname, FILES_PREFIX);
    return handleFileDownload(request, env, corsHeaders, key);
  }
  if (pathname.startsWith(FILES_PREFIX) && method === 'DELETE') {
    const key = extractKeyFromPath(pathname, FILES_PREFIX);
    return handleFileDelete(request, env, corsHeaders, key);
  }

  // --- Tables génériques (classes, matieres, actualites, evenements, eleves,
  //     notifications, etablissement_galerie) ---
  for (const tableName of SIMPLE_TABLES) {
    if (pathname === `/api/${tableName}` && method === 'GET') {
      return handleGenericList(request, env, corsHeaders, tableName);
    }
    if (pathname === `/api/${tableName}` && method === 'POST') {
      return handleGenericCreate(request, env, corsHeaders, tableName);
    }
    const recordMatch = pathname.match(new RegExp(`^/api/${tableName}/([^/]+)$`));
    if (recordMatch && (method === 'PATCH' || method === 'PUT')) {
      return handleGenericUpdate(request, env, corsHeaders, tableName, recordMatch[1]);
    }
    if (recordMatch && method === 'DELETE') {
      return handleGenericDelete(request, env, corsHeaders, tableName, recordMatch[1]);
    }
  }

  return errorResponse('Route introuvable.', 404, 'NOT_FOUND');
}

export default {
  async fetch(request, env, ctx) {
    const corsHeaders = buildCorsHeaders(request, env);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    if (!checkRateLimit(request, env)) {
      return withCors(
        errorResponse('Trop de requêtes, veuillez réessayer plus tard.', 429, 'RATE_LIMITED'),
        corsHeaders
      );
    }

    if (!env.SUPABASE_URL || !env.SUPABASE_ANON_KEY || !env.SUPABASE_SERVICE_ROLE_KEY) {
      return withCors(
        errorResponse('Configuration serveur incomplète.', 500, 'SERVER_MISCONFIGURED'),
        corsHeaders
      );
    }

    try {
      const response = await router(request, env, corsHeaders);
      return withCors(response, corsHeaders);
    } catch (err) {
      return withCors(
        errorResponse('Erreur interne du serveur.', 500, 'INTERNAL_ERROR'),
        corsHeaders
      );
    }
  },
};
