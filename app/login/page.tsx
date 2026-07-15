import { SignInButton } from "@/components/esignet/sign-in-button";

export const dynamic = "force-dynamic";

const MESSAGES: Record<string, string> = {
  esignet_required: "Veuillez vous connecter avec eSignet pour accéder à votre espace.",
  esignet_denied: "La connexion a été annulée ou refusée.",
  invalid_callback: "La session de connexion a expiré. Merci de réessayer.",
  token_exchange: "La connexion a échoué. Merci de réessayer.",
};

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string; logged_out?: string }>;
}) {
  const params = await searchParams;
  const notice = params.logged_out
    ? "Vous êtes déconnecté. La session locale eSignet a été effacée."
    : params.error
      ? MESSAGES[params.error] ?? "Une erreur est survenue. Merci de réessayer."
      : null;

  return (
    <main style={{ maxWidth: 420, margin: "4rem auto", fontFamily: "system-ui" }}>
      <h1>Se connecter</h1>
      <p>Utilisez votre identité numérique eSignet pour accéder à votre espace.</p>
      {notice && (
        <p style={{ padding: "0.75rem", background: "#f0f4ff", borderRadius: 8 }}>
          {notice}
        </p>
      )}
      <SignInButton />
    </main>
  );
}
