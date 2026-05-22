export default function Panel({title, subtitle, children}) {
  return (
    <article className="panel">
      <div className="panel-header">
        <h2>{title}</h2>
        {subtitle ? <span className="muted">{subtitle}</span> : null}
      </div>
      {children}
    </article>
  );
}
