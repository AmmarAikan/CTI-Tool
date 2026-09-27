import type { QueryClient } from '@tanstack/react-query';
import { ApiError, type AcceptedSyncResult, type ExternalJob } from './client';
import { externalQueryKeys } from './externalQueryKeys';

export function externalImportIdentity(job: ExternalJob): string | undefined {
  const value = job.export;
  if (!value?.run_id || !value.dataset_sha256 || !['completed', 'partial'].includes(job.state)) return undefined;
  return `${job.job_id}:${value.run_id}:${value.dataset_sha256}`;
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
