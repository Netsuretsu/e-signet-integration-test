import { generateKeyPair, exportPKCS8, exportJWK } from "jose";
import { randomUUID } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

const OUT_DIR = join(process.cwd(), "keys");

async function main() {
  await mkdir(OUT_DIR, { recursive: true });

  const { publicKey, privateKey } = await generateKeyPair("RS256", {
    modulusLength: 2048,
    extractable: true,
  });

  const kid = randomUUID();

  const privatePem = await exportPKCS8(privateKey);

  const publicJwk = await exportJWK(publicKey);
  publicJwk.kid = kid;
  publicJwk.use = "sig";        
  publicJwk.alg = "RS256";

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
