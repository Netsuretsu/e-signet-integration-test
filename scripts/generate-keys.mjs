/**
 * Génération de la paire de clés pour l'onboarding eSignet.
 *
 * Produit trois fichiers dans ./keys :
 *   - private.pem        -> clé privée PKCS#8 (RESTE côté serveur, jamais commitée)
 *   - public.jwk.json    -> clé publique JWK (à transmettre à l'équipe eSignet)
 *   - env-snippet.txt    -> ESIGNET_PRIVATE_KEY et ESIGNET_KEY_ID prêts à coller
 *
 * Usage :
 *   npm install jose
 *   node scripts/generate-keys.mjs
 *
 * Chaque environnement (local / recette / production) DOIT avoir sa propre paire.
 * Ne jamais réutiliser la clé de développement ailleurs.
 */

import { generateKeyPair, exportPKCS8, exportJWK } from "jose";
import { randomUUID } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

const OUT_DIR = join(process.cwd(), "keys");

async function main() {
  await mkdir(OUT_DIR, { recursive: true });

  // RSA 2048, algorithme de signature RS256 (attendu par eSignet Bénin).
  // extractable: true est nécessaire pour pouvoir exporter les clés.
  const { publicKey, privateKey } = await generateKeyPair("RS256", {
    modulusLength: 2048,
    extractable: true,
  });

  // kid explicite et stable : il devra correspondre exactement à ESIGNET_KEY_ID
  // et au header `kid` de l'assertion client.
  const kid = randomUUID();

  // 1) Clé privée au format PKCS#8 (texte PEM multiligne).
  const privatePem = await exportPKCS8(privateKey);

  // 2) Clé publique au format JWK, enrichie des métadonnées attendues à l'onboarding.
  const publicJwk = await exportJWK(publicKey);
  publicJwk.kid = kid;
  publicJwk.use = "sig";        // clé de signature
  publicJwk.alg = "RS256";

  // 3) Snippet .env.local : la clé privée sur variable d'environnement.
  // Les sauts de ligne sont encodés en \n pour tenir sur une seule ligne de .env.
  const privateForEnv = privatePem.trimEnd().replace(/\n/g, "\\n");
  const envSnippet =
    `ESIGNET_KEY_ID=${kid}\n` +
    `ESIGNET_PRIVATE_KEY="${privateForEnv}"\n`;

  await writeFile(join(OUT_DIR, "private.pem"), privatePem, "utf8");
  await writeFile(
    join(OUT_DIR, "public.jwk.json"),
    JSON.stringify(publicJwk, null, 2) + "\n",
    "utf8",
  );
  await writeFile(join(OUT_DIR, "env-snippet.txt"), envSnippet, "utf8");

  console.log("Clés générées dans ./keys");
  console.log("  kid :", kid);
  console.log("");
  console.log("À TRANSMETTRE À eSIGNET  -> keys/public.jwk.json");
  console.log("À GARDER CÔTÉ SERVEUR    -> keys/private.pem (NE PAS COMMITER)");
  console.log("À COLLER DANS .env.local -> keys/env-snippet.txt");
  console.log("");
  console.log("JWK publique :");
  console.log(JSON.stringify(publicJwk, null, 2));
}

main().catch((err) => {
  console.error("Échec de génération :", err);
  process.exit(1);
});
