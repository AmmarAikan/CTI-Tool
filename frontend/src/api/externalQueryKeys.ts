export const externalQueryKeys = {
  root: ['external'] as const,
  sources: () => ['external', 'sources'] as const,
  reviews: () => ['external', 'reviews'] as const,
  reviewLifecycle: () => ['external', 'review-lifecycle'] as const,
  acceptedRecords: (offset = 0, search = '') => ['external', 'accepted-records', offset, search] as const,
  acceptedRecord: (id: string) => ['external', 'accepted-record', id] as const,
  jobs: () => ['external', 'jobs'] as const,
  processingRun: (runId: string) => ['external', 'processing-run', runId] as const,
};
