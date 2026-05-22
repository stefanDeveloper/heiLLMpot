export default function Badge({value}) {
  const text = value || "unknown";
  const className = String(text).toLowerCase().replaceAll(/[^a-z0-9_-]/g, "_");
  return <span className={`badge ${className}`}>{text}</span>;
}
