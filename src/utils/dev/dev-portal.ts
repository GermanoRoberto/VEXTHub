export function isDevPortalEnabled() {
  return process.env.NODE_ENV === "development" || process.env.VEXTHUB_DEV_PORTAL === "true";
}
