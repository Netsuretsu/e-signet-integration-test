"use client";

import { useEffect, useRef } from "react";

declare global {
  interface Window {
    SignInWithEsignetButton?: {
      init(config: unknown): void | Promise<unknown>;
    };
  }
}

const PLUGIN_ID = "esignet-sign-in-plugin";

let bootstrapStarted = false;

export function SignInButton() {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (bootstrapStarted) return;
    bootstrapStarted = true;

    const clientId = process.env.NEXT_PUBLIC_ESIGNET_CLIENT_ID;
    const pluginUrl = process.env.NEXT_PUBLIC_ESIGNET_PLUGIN_URL;
    const authorizeUri = process.env.NEXT_PUBLIC_ESIGNET_AUTHORIZE_URL;
    const scope = process.env.NEXT_PUBLIC_ESIGNET_SCOPE;

    if (!clientId || !pluginUrl || !authorizeUri || !scope) {
      console.error("Configuration eSignet publique incomplète");
      bootstrapStarted = false;
      return;
    }

    async function bootstrap() {
      const container = containerRef.current;
      if (!container || !window.SignInWithEsignetButton) return;


      const prep = await fetch("/api/auth/esignet/prepare", {
        cache: "no-store",
        credentials: "same-origin",
      });
      if (!prep.ok) {
        console.error("Échec de /prepare :", prep.status);
        bootstrapStarted = false;
        return;
      }
      const { state, nonce } = await prep.json();

      await window.SignInWithEsignetButton.init({
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
    }

    const existing = document.getElementById(
      PLUGIN_ID,
    ) as HTMLScriptElement | null;

    if (existing) {
      if (window.SignInWithEsignetButton) {
        void bootstrap();
      } else {
        existing.addEventListener("load", () => void bootstrap());
      }
      return;
    }

    const script = document.createElement("script");
    script.id = PLUGIN_ID;
    script.src = pluginUrl;
    script.async = true;
    script.addEventListener("load", () => void bootstrap());
    script.addEventListener("error", () => {
      console.error("Échec du chargement du plugin eSignet");
      bootstrapStarted = false;
    });
    document.body.appendChild(script);
  }, []);

  return <div ref={containerRef} aria-label="Connexion eSignet" />;
}