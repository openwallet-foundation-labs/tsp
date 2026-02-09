use criterion::Criterion;
use std::time::Duration;

pub fn default_config() -> Criterion {
    Criterion::default()
        .without_plots()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(5))
        .sample_size(30)
}
