// Garde serveur avant rendu de l'espace privé. Aucun accès sur la simple
// présence d'un paramètre de callback : seule une session valide passe.

import { redirect } from "next/navigation";
import { getEsignetSession } from "@/lib/esignet-session";

export const dynamic = "force-dynamic";

export default async function DashboardPage() {
  const session = await getEsignetSession();
  if (!session) redirect("/login?esignet_required=1");

  const shown = (v?: string) => v ?? "Non partagé";

  return (
    <main style={{ maxWidth: 640, margin: "2rem auto", fontFamily: "system-ui" }}>
      <p style={{ color: "green" }}>✓ Connexion eSignet validée</p>
      <h1>Mes données</h1>
      <dl>
        <dt>Nom</dt>
        <dd>{session.name}</dd>
        <dt>E-mail</dt>
        <dd>{shown(session.email)}</dd>
        <dt>Téléphone</dt>
        <dd>{shown(session.phoneNumber)}</dd>
        <dt>Date de naissance</dt>
        <dd>{shown(session.birthdate)}</dd>
        <dt>Genre</dt>
        <dd>{shown(session.gender)}</dd>
        <dt>Adresse</dt>
        <dd>{shown(session.address)}</dd>
      </dl>
      <p style={{ fontSize: "0.8rem", color: "#666" }}>
        Source des données : {session.claimsSource}
      </p>
      <form action="/api/auth/esignet/logout" method="post">
        <button type="submit">Déconnexion</button>
      </form>
    </main>
  );
}
