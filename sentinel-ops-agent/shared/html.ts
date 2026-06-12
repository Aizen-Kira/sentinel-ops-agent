const HTML_ESCAPE_LOOKUP: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

export function escapeHtml(value: unknown): string {
  if (value === null || value === undefined) {
    return "";
  }

  return String(value).replace(/[&<>"']/g, (char) => HTML_ESCAPE_LOOKUP[char]);
}
