"use client";

import { useEffect, useRef } from "react";

declare global {
  interface Window {
    SignInWithEsignetButton?: {
      init(config: unknown): void;
    };
  }
}

const PLUGIN_ID = "esignet-sign-in-plugin";

export function SignInButton() {
  const containerRef = useRef<HTMLDivElement>(null);
  const initialized = useRef(false);

  useEffect(() => {
    if (initialized.current) return;

    const clientId = process.env.NEXT_PUBLIC_ESIGNET_CLIENT_ID;
    const pluginUrl = process.env.NEXT_PUBLIC_ESIGNET_PLUGIN_URL;
    const authorizeUri = process.env.NEXT_PUBLIC_ESIGNET_AUTHORIZE_URL;
    const scope = process.env.NEXT_PUBLIC_ESIGNET_SCOPE;

    if (!clientId || !pluginUrl || !authorizeUri || !scope) {
      console.error("Configuration eSignet publique incomplète");
      return;
    }

    async function initButton() {
      if (initialized.current || !window.SignInWithEsignetButton) return;
      const container = containerRef.current;
      if (!container) return;

      try {
        const { state, nonce } = await fetch("/api/auth/esignet/prepare", {
          cache: "no-store",
          credentials: "same-origin",
        }).then((r) => r.json());

        window.SignInWithEsignetButton.init({
          oidcConfig: {
            authorizeUri,
            client_id: clientId,
            redirect_uri: `${window.location.origin}/auth/callback`,
            scope,
            response_type: "code",
            state,
            nonce,
            prompt: process.env.NEXT_PUBLIC_ESIGNET_PROMPT || "consent",
            display: process.env.NEXT_PUBLIC_ESIGNET_DISPLAY || "page",
          },
          buttonConfig: {
            type: "standard",
            theme: "filled_black",
            shape: "soft_edges",
            width: "100%",
            labelText: "Continuer avec eSignet",
          },
          signInElement: container,
        });
        initialized.current = true;
      } catch (e) {
        console.error("Échec initialisation bouton eSignet", e);
      }
    }

    const existing = document.getElementById(PLUGIN_ID) as HTMLScriptElement | null;
    if (existing) {
      if (window.SignInWithEsignetButton) void initButton();
      else existing.addEventListener("load", () => void initButton());
      return;
    }

    const script = document.createElement("script");
    script.id = PLUGIN_ID;
    script.src = pluginUrl;
    script.async = true;
    script.addEventListener("load", () => void initButton());
    script.addEventListener("error", () =>
      console.error("Échec du chargement du plugin eSignet"),
    );
    document.body.appendChild(script);
  }, []);

  return <div ref={containerRef} aria-label="Connexion eSignet" />;
}
