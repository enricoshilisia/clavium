// The Clavium control plane this build talks to. Fixed at build time:
// pointing a release at the wrong server is a mistake worth catching then.
// Self-hosted (enterprise) builds set VITE_CLAVIUM_API when building.
export const CONTROL_PLANE_URL: string =
  import.meta.env.VITE_CLAVIUM_API || "https://clavium-api.172-169-233-189.sslip.io";
