export function formatNumber(value) {
  return new Intl.NumberFormat().format(Number(value || 0));
}

export function formatTime(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  });
}

export function shortId(value) {
  return value ? String(value).slice(0, 8) : "";
}
