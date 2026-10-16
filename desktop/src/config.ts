// The Clavium control plane this desktop build talks to for account
// login and encrypted vault backup. A build-time constant, not a
// runtime setting — pointing a release build at the wrong control plane
// is a mistake worth catching at build time, not something to make
// configurable in the UI before there is a reason to.
export const CONTROL_PLANE_URL = "https://clavium-api.172-169-233-189.sslip.io";
