// The Clavium control plane this app talks to.
//
// Default: fixed at build time (self-hosted builds set VITE_CLAVIUM_API).
// An organization can point its computers at its own server with the
// ServerUrl managed setting (Intune / Group Policy, see managed.ts),
// applied once at startup before any request is made.
const BUILD_DEFAULT: string = import.meta.env.VITE_CLAVIUM_API || "https://clavium-api.172-169-233-189.sslip.io";

let current = BUILD_DEFAULT;

export function controlPlaneUrl(): string {
  return current;
}

export function setControlPlaneUrl(url: string | null | undefined) {
  current = (url || BUILD_DEFAULT).replace(/\/+$/, "");
}
