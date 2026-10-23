// Thin client for the FastAPI backend. Every call throws an Error with a readable message.

async function request(path, options) {
  let response;
  try {
    response = await fetch(path, options);
  } catch {
    throw new Error("Cannot reach the API. Start it with: uvicorn backend.app:app");
  }
  if (!response.ok) {
    let detail = `Request failed (${response.status})`;
    try {
      const body = await response.json();
      if (typeof body.detail === "string") detail = body.detail;
      else if (Array.isArray(body.detail)) detail = body.detail.map((d) => d.msg).join("; ");
    } catch { /* keep the generic message */ }
    throw new Error(detail);
  }
  return response;
}

const json = (body) => ({
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});
const q = (policy) => `?policy=${encodeURIComponent(policy)}`;

export const api = {
  health: () => request("/api/health").then((r) => r.json()),
  policies: () => request("/api/policies").then((r) => r.json()),
  methodology: (policy) => request(`/api/methodology${q(policy)}`).then((r) => r.json()),
  samples: () => request("/api/samples").then((r) => r.json()),
  sample: (name, policy) => request(`/api/samples/${encodeURIComponent(name)}${q(policy)}`).then((r) => r.json()),
  assess: (doc, policy) => request(`/api/assess${q(policy)}`, json(doc)).then((r) => r.json()),
  upload: (file, policy) => {
    const form = new FormData();
    form.append("file", file);
    return request(`/api/upload${q(policy)}`, { method: "POST", body: form }).then((r) => r.json());
  },
  compare: (before, after) => request("/api/compare", json({ before, after })).then((r) => r.json()),
  explain: (assessed) => request("/api/explain", json({ assessed })).then((r) => r.json()),
  report: (assessed, explanation, comparison, format) =>
    request(`/api/report?format=${format}`, json({ assessed, explanation, comparison })).then((r) => r.text()),
};

// The assessed document is the analyzer's document plus three blocks; drop them to re-assess.
export function stripAssessment(doc) {
  const { findings, posture, assessment, ...analysis } = doc;
  return analysis;
}
