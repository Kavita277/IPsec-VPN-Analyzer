export const SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"];

// Evidence lookups shared by several components.
export const FIELD_SUFFIX = { encryption: ".tf.id.encr", integrity: ".tf.id.integ", dh_group: ".tf.id.dh" };
export const PARAM_LABEL = { encryption: "Encryption", integrity: "Integrity", dh_group: "DH group" };

export function value(v) {
  if (v === null || v === undefined) return "not observed";
  if (Array.isArray(v)) return v.join(", ");
  if (typeof v === "object") return Object.entries(v).map(([k, x]) => `${k}=${x}`).join(", ");
  return String(v);
}
