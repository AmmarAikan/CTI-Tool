import { Component, type ErrorInfo, type ReactNode } from 'react';

export class AppErrorBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  componentDidCatch(_error: Error, _info: ErrorInfo) { /* Never render or forward runtime details. */ }
  render() {
    if (this.state.failed) return <main className="fatal-state" role="alert"><strong>تعذر عرض هذه الصفحة بأمان</strong><p>أعد تحميل التطبيق أو ارجع إلى لوحة المتابعة.</p><a className="button button-primary" href="/">العودة إلى لوحة المتابعة</a></main>;
    return this.props.children;
  }
}

export function NotFound() { return <section className="page-section"><div className="state-panel"><strong>الصفحة غير موجودة</strong><p>تحقق من الرابط أو ارجع إلى لوحة المتابعة.</p><a className="button button-secondary" href="/">لوحة المتابعة</a></div></section>; }
