# Intégration eSignet Bénin — Next.js (App Router)

Squelette de Relying Party OIDC pour eSignet Bénin, aligné sur le guide ANIP.
Le navigateur ne reçoit ni clé privée ni logique de validation : tout ce qui est
sensible vit côté serveur.

## Prérequis

- Next.js 14+ (App Router) et Node.js 18+
- Un client eSignet de développement **déjà onboardé** avec le callback exact
  `http://localhost:3000/auth/callback`
- La paire de clés RSA correspondant à la JWK publique transmise à eSignet

## 1. Générer la paire de clés (prérequis bloquant)

```bash
npm install jose
node scripts/generate-keys.mjs
```

Produit dans `./keys` :

- `public.jwk.json` → **à transmettre à l'équipe eSignet**
- `private.pem` → reste côté serveur, jamais commité
- `env-snippet.txt` → `ESIGNET_KEY_ID` et `ESIGNET_PRIVATE_KEY` prêts à coller

Chaque environnement (local / recette / production) a sa **propre** paire.

## 2. Configurer

```bash
cp .env.example .env.local
# puis compléter avec le client-id, le snippet de keys/env-snippet.txt,
# et un ESIGNET_SESSION_SECRET aléatoire fort
```

Générer un secret de session :

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

## 3. Lancer

```bash
npm ci
npm run dev
# Point d'entrée : http://localhost:3000/login
```

## Arborescence

| Fichier | Rôle |
|---------|------|
| `scripts/generate-keys.mjs` | Génère la paire RSA + JWK publique |
| `components/esignet/sign-in-button.tsx` | Charge le plugin, initialise le bouton |
| `app/api/auth/esignet/prepare/route.ts` | `state`/`nonce` + cookie de tentative |
| `app/auth/callback/route.ts` | Orchestration du callback + redirections |
| `app/api/auth/esignet/logout/route.ts` | Destruction de session |
| `lib/esignet-auth.ts` | Assertion client, token exchange, validation JWT/JWKS, UserInfo, JWE |
| `lib/esignet-session.ts` | Lecture de la session (garde serveur) |
| `lib/esignet-cookies.ts` | Effacement cohérent des cookies |
| `lib/esignet-types.ts` | Contrat du profil applicatif |
| `app/dashboard/page.tsx` | Garde serveur avant l'espace privé |
| `app/login/page.tsx` | Page publique + messages d'état |

## Invariant du callback

L'URI envoyée à `/authorize`, celle envoyée au token endpoint et celle
enregistrée chez eSignet doivent être **identiques au caractère près**
(protocole, domaine, port, chemin). C'est la cause n°1 d'échec.

## Matrice de recette (positifs + négatifs)

- `/login` charge le plugin, bouton visible
- Clic → écran eSignet avec le nom du client ANIP
- Accès direct `/dashboard` sans session → redirection login
- Altération du `state` → `invalid_callback`, pas de dashboard
- Non-partage d'un attribut → « Non partagé », jamais de valeur fictive
- Déconnexion → les deux cookies expirés
- Retour arrière après logout → dashboard toujours inaccessible

## Points d'attention eSignet Bénin

- Les attributs métier ne sont pas dans l'ID token : chargés depuis UserInfo.
- UserInfo peut être **JWS signé** (vérifié via JWKS) ou JSON.
- `ESIGNET_ALLOW_UNVERIFIED_USERINFO` reste `false` : exception transport
  temporaire uniquement, à documenter et retirer.
- `NEXT_PUBLIC_ESIGNET_CLAIMS` vide tant que l'onboarding des claims n'est pas
  confirmé ; les scopes suffisent à déclencher les claims associés.

## Avant une ouverture à des utilisateurs réels

Le guide ANIP identifie des écarts à fermer : **PKCE S256**, découverte OIDC
dynamique, résolution formelle de la signature UserInfo, rotation des clés en
coffre/HSM, tests de charge, revue de confidentialité et homologation sécurité.
