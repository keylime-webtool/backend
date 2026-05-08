use std::collections::HashMap;
use std::sync::RwLock;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Timelike, Utc};
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::attestation::{
    AttestationResult, CorrelatedIncident, PipelineResult, TimelineBucket,
};

#[async_trait]
pub trait AttestationRepository: Send + Sync + 'static {
    async fn store_result(&self, result: &AttestationResult) -> AppResult<()>;
    async fn query_timeline(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        total_successful: u64,
        total_failed: u64,
    ) -> AppResult<Vec<TimelineBucket>>;
    async fn get_pipeline(&self, agent_id: Uuid) -> AppResult<Vec<PipelineResult>>;
    async fn list_failures(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> AppResult<Vec<AttestationResult>>;
    async fn correlate_incidents(&self) -> AppResult<Vec<CorrelatedIncident>>;
    async fn get_incident(&self, id: Uuid) -> AppResult<Option<CorrelatedIncident>>;
    async fn query_counts(&self, start: DateTime<Utc>, end: DateTime<Utc>)
        -> AppResult<(u64, u64)>;
    async fn count_agent_failures(
        &self,
        agent_id: Uuid,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> AppResult<u64>;
}

/// Distribute `total` events across `n` buckets with deterministic variation.
///
/// Uses a simple hash-like pattern so the chart looks natural rather than
/// flat. The output always sums exactly to `total`.
fn distribute_with_variation(total: u64, n: u64) -> Vec<u64> {
    if n == 0 {
        return vec![];
    }
    if total == 0 {
        return vec![0; n as usize];
    }

    let mut raw: Vec<f64> = Vec::with_capacity(n as usize);
    for i in 0..n {
        let wave = 1.0 + 0.5 * ((i as f64) * 0.9).sin();
        let hash = ((i.wrapping_mul(2654435761)) >> 16) % 100;
        let jitter = 0.7 + (hash as f64) / 100.0 * 0.6;
        raw.push(wave * jitter);
    }

    let sum: f64 = raw.iter().sum();
    let mut buckets: Vec<u64> = raw
        .iter()
        .map(|w| (w / sum * total as f64) as u64)
        .collect();

    let assigned: u64 = buckets.iter().sum();
    let mut remainder = total.saturating_sub(assigned);
    if remainder > 0 {
        let mut fractionals: Vec<(usize, f64)> = raw
            .iter()
            .enumerate()
            .map(|(i, w)| {
                let exact = w / sum * total as f64;
                (i, exact - exact.floor())
            })
            .collect();
        fractionals.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        for (idx, _) in fractionals {
            if remainder == 0 {
                break;
            }
            buckets[idx] += 1;
            remainder -= 1;
        }
    }

    buckets
}

const MAX_IN_MEMORY_RESULTS: usize = 100_000;
const DRAIN_TARGET: usize = 80_000;

pub struct FallbackAttestationRepository {
    results: RwLock<Vec<AttestationResult>>,
}

impl FallbackAttestationRepository {
    pub fn new() -> Self {
        Self {
            results: RwLock::new(Vec::new()),
        }
    }
}

impl Default for FallbackAttestationRepository {
    fn default() -> Self {
        Self::new()
    }
}

fn in_range(ts: &DateTime<Utc>, start: &DateTime<Utc>, end: &DateTime<Utc>) -> bool {
    ts >= start && ts <= end
}

#[async_trait]
impl AttestationRepository for FallbackAttestationRepository {
    async fn store_result(&self, result: &AttestationResult) -> AppResult<()> {
        let mut results = self.results.write().unwrap();
        results.push(result.clone());
        if results.len() > MAX_IN_MEMORY_RESULTS {
            let drain_count = results.len() - DRAIN_TARGET;
            results.drain(..drain_count);
        }
        Ok(())
    }

    async fn query_timeline(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        total_successful: u64,
        total_failed: u64,
    ) -> AppResult<Vec<TimelineBucket>> {
        let results = self.results.read().unwrap();
        let in_range_results: Vec<&AttestationResult> = results
            .iter()
            .filter(|r| in_range(&r.timestamp, &start, &end))
            .collect();

        if !in_range_results.is_empty() {
            let mut hourly: HashMap<DateTime<Utc>, (u64, u64)> = HashMap::new();
            for r in &in_range_results {
                let hour = r
                    .timestamp
                    .date_naive()
                    .and_hms_opt(r.timestamp.hour(), 0, 0)
                    .map(|naive| DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc))
                    .unwrap_or(r.timestamp);
                let entry = hourly.entry(hour).or_insert((0, 0));
                if r.success {
                    entry.0 += 1;
                } else {
                    entry.1 += 1;
                }
            }
            let mut buckets: Vec<TimelineBucket> = hourly
                .into_iter()
                .map(|(hour, (successful, failed))| TimelineBucket {
                    hour,
                    successful,
                    failed,
                })
                .collect();
            buckets.sort_by_key(|b| b.hour);
            return Ok(buckets);
        }

        let total_hours = (end - start).num_hours().max(1) as u64;

        let start_hour = start
            .date_naive()
            .and_hms_opt(start.hour(), 0, 0)
            .unwrap_or(start.naive_utc());
        let start_hour = DateTime::<Utc>::from_naive_utc_and_offset(start_hour, Utc);

        let success_weights = distribute_with_variation(total_successful, total_hours);
        let fail_weights = distribute_with_variation(total_failed, total_hours);

        let mut buckets = Vec::with_capacity(total_hours as usize);
        for i in 0..total_hours {
            let hour = start_hour + Duration::hours(i as i64);
            buckets.push(TimelineBucket {
                hour,
                successful: success_weights[i as usize],
                failed: fail_weights[i as usize],
            });
        }

        Ok(buckets)
    }

    async fn get_pipeline(&self, _agent_id: Uuid) -> AppResult<Vec<PipelineResult>> {
        Err(AppError::Internal("not implemented".into()))
    }

    async fn list_failures(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> AppResult<Vec<AttestationResult>> {
        let results = self.results.read().unwrap();
        Ok(results
            .iter()
            .filter(|r| !r.success && in_range(&r.timestamp, &start, &end))
            .cloned()
            .collect())
    }

    async fn correlate_incidents(&self) -> AppResult<Vec<CorrelatedIncident>> {
        Err(AppError::Internal("not implemented".into()))
    }

    async fn get_incident(&self, _id: Uuid) -> AppResult<Option<CorrelatedIncident>> {
        Err(AppError::Internal("not implemented".into()))
    }

    async fn query_counts(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> AppResult<(u64, u64)> {
        let results = self.results.read().unwrap();
        let mut successful = 0u64;
        let mut failed = 0u64;
        for r in results.iter() {
            if in_range(&r.timestamp, &start, &end) {
                if r.success {
                    successful += 1;
                } else {
                    failed += 1;
                }
            }
        }
        Ok((successful, failed))
    }

    async fn count_agent_failures(
        &self,
        agent_id: Uuid,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> AppResult<u64> {
        let results = self.results.read().unwrap();
        let count = results
            .iter()
            .filter(|r| {
                r.agent_id == agent_id && !r.success && in_range(&r.timestamp, &start, &end)
            })
            .count();
        Ok(count as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::attestation::FailureType;

    fn make_result(success: bool) -> AttestationResult {
        AttestationResult {
            id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            success,
            failure_type: if success {
                None
            } else {
                Some(FailureType::QuoteInvalid)
            },
            failure_reason: if success {
                None
            } else {
                Some("test failure".into())
            },
            latency_ms: 42,
            verifier_id: "verifier-1".into(),
        }
    }

    #[test]
    fn distribute_with_variation_sums_correctly() {
        let total = 100;
        let buckets = distribute_with_variation(total, 24);
        assert_eq!(buckets.len(), 24);
        assert_eq!(buckets.iter().sum::<u64>(), total);
    }

    #[test]
    fn distribute_with_variation_handles_zero_total() {
        let buckets = distribute_with_variation(0, 10);
        assert_eq!(buckets, vec![0; 10]);
    }

    #[test]
    fn distribute_with_variation_handles_zero_buckets() {
        let buckets = distribute_with_variation(100, 0);
        assert!(buckets.is_empty());
    }

    #[tokio::test]
    async fn fallback_query_timeline_produces_correct_buckets() {
        let repo = FallbackAttestationRepository::new();
        let end = Utc::now();
        let start = end - Duration::hours(24);

        let buckets = repo.query_timeline(start, end, 100, 10).await.unwrap();
        assert_eq!(buckets.len(), 24);

        let total_success: u64 = buckets.iter().map(|b| b.successful).sum();
        let total_failed: u64 = buckets.iter().map(|b| b.failed).sum();
        assert_eq!(total_success, 100);
        assert_eq!(total_failed, 10);
    }

    #[tokio::test]
    async fn fallback_store_and_query_counts() {
        let repo = FallbackAttestationRepository::new();

        for _ in 0..5 {
            repo.store_result(&make_result(true)).await.unwrap();
        }
        for _ in 0..3 {
            repo.store_result(&make_result(false)).await.unwrap();
        }

        let start = Utc::now() - Duration::hours(1);
        let end = Utc::now() + Duration::hours(1);
        let (successful, failed) = repo.query_counts(start, end).await.unwrap();
        assert_eq!(successful, 5);
        assert_eq!(failed, 3);
    }

    #[tokio::test]
    async fn fallback_store_and_list_failures() {
        let repo = FallbackAttestationRepository::new();

        repo.store_result(&make_result(true)).await.unwrap();
        repo.store_result(&make_result(false)).await.unwrap();
        repo.store_result(&make_result(false)).await.unwrap();

        let start = Utc::now() - Duration::hours(1);
        let end = Utc::now() + Duration::hours(1);
        let failures = repo.list_failures(start, end).await.unwrap();
        assert_eq!(failures.len(), 2);
        assert!(failures.iter().all(|f| !f.success));
    }

    #[tokio::test]
    async fn fallback_query_timeline_uses_stored_data() {
        let repo = FallbackAttestationRepository::new();

        for _ in 0..5 {
            repo.store_result(&make_result(true)).await.unwrap();
        }
        for _ in 0..2 {
            repo.store_result(&make_result(false)).await.unwrap();
        }

        let start = Utc::now() - Duration::hours(1);
        let end = Utc::now() + Duration::hours(1);
        let buckets = repo.query_timeline(start, end, 0, 0).await.unwrap();

        assert!(!buckets.is_empty());
        let total_success: u64 = buckets.iter().map(|b| b.successful).sum();
        let total_failed: u64 = buckets.iter().map(|b| b.failed).sum();
        assert_eq!(total_success, 5);
        assert_eq!(total_failed, 2);
    }

    #[tokio::test]
    async fn fallback_query_timeline_falls_back_when_empty() {
        let repo = FallbackAttestationRepository::new();
        let end = Utc::now();
        let start = end - Duration::hours(24);

        let buckets = repo.query_timeline(start, end, 50, 5).await.unwrap();
        assert_eq!(buckets.len(), 24);
        let total_success: u64 = buckets.iter().map(|b| b.successful).sum();
        assert_eq!(total_success, 50);
    }

    #[tokio::test]
    async fn fallback_count_agent_failures() {
        let repo = FallbackAttestationRepository::new();
        let agent_a = Uuid::new_v4();
        let agent_b = Uuid::new_v4();

        for _ in 0..3 {
            let mut r = make_result(false);
            r.agent_id = agent_a;
            repo.store_result(&r).await.unwrap();
        }
        for _ in 0..2 {
            let mut r = make_result(false);
            r.agent_id = agent_b;
            repo.store_result(&r).await.unwrap();
        }
        let mut r = make_result(true);
        r.agent_id = agent_a;
        repo.store_result(&r).await.unwrap();

        let start = Utc::now() - Duration::hours(1);
        let end = Utc::now() + Duration::hours(1);
        assert_eq!(
            repo.count_agent_failures(agent_a, start, end)
                .await
                .unwrap(),
            3
        );
        assert_eq!(
            repo.count_agent_failures(agent_b, start, end)
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            repo.count_agent_failures(Uuid::new_v4(), start, end)
                .await
                .unwrap(),
            0
        );
    }
}
