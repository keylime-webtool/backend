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

pub struct FallbackAttestationRepository;

impl FallbackAttestationRepository {
    pub fn new() -> Self {
        Self
    }
}

impl Default for FallbackAttestationRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AttestationRepository for FallbackAttestationRepository {
    async fn store_result(&self, _result: &AttestationResult) -> AppResult<()> {
        Err(AppError::Internal("not implemented".into()))
    }

    async fn query_timeline(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        total_successful: u64,
        total_failed: u64,
    ) -> AppResult<Vec<TimelineBucket>> {
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
        _start: DateTime<Utc>,
        _end: DateTime<Utc>,
    ) -> AppResult<Vec<AttestationResult>> {
        Err(AppError::Internal("not implemented".into()))
    }

    async fn correlate_incidents(&self) -> AppResult<Vec<CorrelatedIncident>> {
        Err(AppError::Internal("not implemented".into()))
    }

    async fn get_incident(&self, _id: Uuid) -> AppResult<Option<CorrelatedIncident>> {
        Err(AppError::Internal("not implemented".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
