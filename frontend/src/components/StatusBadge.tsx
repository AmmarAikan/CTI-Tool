export function StatusBadge({ status }: { status: string }) {
  const normalized = status.toLowerCase();
  const tone = normalized === 'ok' || normalized === 'enabled' || normalized === 'healthy' ? 'success' : normalized === 'disabled' ? 'muted' : 'warning';
  return <span className={`status-badge status-${tone}`}><span aria-hidden="true" className="status-dot" />{status}</span>;
}
