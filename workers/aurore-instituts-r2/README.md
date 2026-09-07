# Aurore Instituts — Worker R2

Worker Cloudflare dédié à la gestion sécurisée des fichiers du projet **Aurore — Section Instituts**.

Ce Worker est indépendant du Worker utilisé par **Aurore — Section Archives**.

## Architecture

Vercel
→ Cloudflare Worker `aurore-instituts-r2`
→ R2 privé `aurore-instituts`

Supabase conserve les métadonnées des documents.

## Configuration

Le fichier `wrangler.toml` contient les variables non secrètes :

- `SUPABASE_URL`
- `ALLOWED_ORIGINS`

Les secrets doivent être configurés directement dans Cloudflare :

- `SUPABASE_JWT_SECRET`
- `SUPABASE_SERVICE_ROLE_KEY`

Ils ne doivent jamais être ajoutés au dépôt GitHub.

## Bucket R2

Bucket utilisé :

`aurore-instituts`

Le bucket reste privé.

Les fichiers sont identifiés par une clé de stockage R2, par exemple :

`etablissements/{etablissement_id}/documents/{fichier}`

Il est recommandé de conserver cette clé dans Supabase (`storage_key` ou `r2_object_key`) plutôt qu'une URL publique permanente.

## API

### POST `/upload`

Permet d'envoyer un fichier vers R2.

Rôles autorisés :

- `owner`
- `admin`
- `teacher`

Le fichier est associé à un établissement.

### GET `/file?key=...`

Permet de récupérer un fichier depuis R2.

L'utilisateur doit être membre de l'établissement concerné.

La récupération prend en charge les requêtes HTTP `Range`, notamment pour les PDF et les médias.

### DELETE `/file?key=...`

Supprime un fichier du bucket R2.

Rôles autorisés :

- `owner`
- `admin`
- `teacher`

## Sécurité

Le Worker :

- vérifie le JWT Supabase ;
- vérifie l'appartenance à l'établissement ;
- vérifie les rôles autorisés pour l'écriture ;
- valide les UUID ;
- contrôle les clés de stockage R2 ;
- bloque les chemins dangereux ;
- limite les uploads à 512 MiB ;
- conserve le bucket R2 privé ;
- n'expose aucune clé secrète dans le dépôt.

## Déploiement

Le Worker sera déployé avec Wrangler depuis Cloudflare.

Les secrets seront ajoutés côté Cloudflare et jamais dans GitHub.

## Projet

Projet Supabase :

`aurore-instituts`

Référence Supabase :

`fdstrbqvkemtjyxxaxbj`

Worker :

`aurore-instituts-r2`
