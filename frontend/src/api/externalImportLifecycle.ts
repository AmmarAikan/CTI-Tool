import type { QueryClient } from '@tanstack/react-query';
import { ApiError, type AcceptedSyncResult, type ExternalJob } from './client';
import { externalQueryKeys } from './externalQueryKeys';

export function externalImportIdentity(job: ExternalJob): string | undefined {
  const value = job.export;
  if (!['completed', 'partial'].includes(job.state) || value?.status !== 'completed') return undefined;
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/.test(value.run_id) || !/^[a-f0-9]{64}$/i.test(value.dataset_sha256 || '')) return undefined;
  return `${job.job_id}:${value.run_id}:${value.dataset_sha256}`;
}

export function externalImportBlockReason(job: ExternalJob): 'export_incomplete' | 'export_identity_missing' | undefined {
  if (!['completed', 'partial'].includes(job.state)) return undefined;
  if (job.export?.status !== 'completed') return 'export_incomplete';
  return externalImportIdentity(job) ? undefined : 'export_identity_missing';
}

export function isAbortError(error: unknown) {
  return error instanceof DOMException && error.name === 'AbortError';
}

export function isRetryableExternalImportError(error: unknown) {
  return error instanceof TypeError || (error instanceof ApiError && error.retryable && [408, 503, 504].includes(error.status));
}

export async function refreshAfterExternalImport(queryClient: QueryClient, result: AcceptedSyncResult) {
  await Promise.all([
    queryClient.invalidateQueries({ queryKey: ['external', 'accepted-records'], refetchType: 'active' }),
    queryClient.invalidateQueries({ queryKey: externalQueryKeys.reviews(), refetchType: 'active' }),
    queryClient.invalidateQueries({ queryKey: externalQueryKeys.processingRun(result.run_id), refetchType: 'active' }),
    queryClient.invalidateQueries({ queryKey: ['center-summary'], exact: true, refetchType: 'active' }),
    queryClient.invalidateQueries({ queryKey: ['center-events'], exact: true, refetchType: 'active' }),
    queryClient.invalidateQueries({ queryKey: ['center-indicators'], exact: true, refetchType: 'active' }),
    queryClient.invalidateQueries({ queryKey: ['dashboard-summary'], exact: true, refetchType: 'active' }),
    queryClient.invalidateQueries({ queryKey: ['indicator-summary'], exact: true, refetchType: 'active' }),
  ]);
}
