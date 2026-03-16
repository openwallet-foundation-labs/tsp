use crate::layout::DEFAULT_PACKAGE_ROOT;
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompleteCase {
    Cc001,
    Cc002,
    Cc003,
}

impl CompleteCase {
    pub fn case_id(self) -> &'static str {
        match self {
            Self::Cc001 => "CC-001",
            Self::Cc002 => "CC-002",
            Self::Cc003 => "CC-003",
        }
    }

    pub fn artifact_dir_name(self) -> &'static str {
        match self {
            Self::Cc001 => "artifact-set.cc-001",
            Self::Cc002 => "artifact-set.cc-002",
            Self::Cc003 => "artifact-set.cc-003",
        }
    }

    pub fn review_dir_name(self) -> &'static str {
        match self {
            Self::Cc001 => "review-set.cc-001",
            Self::Cc002 => "review-set.cc-002",
            Self::Cc003 => "review-set.cc-003",
        }
    }

    pub fn short_id(self) -> &'static str {
        match self {
            Self::Cc001 => "cc-001",
            Self::Cc002 => "cc-002",
            Self::Cc003 => "cc-003",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingFamily {
    Direct,
    Mechanism,
    Negative,
    Nested,
    Routed,
}

impl BindingFamily {
    pub fn as_dir_name(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Mechanism => "mechanism",
            Self::Negative => "negative",
            Self::Nested => "nested",
            Self::Routed => "routed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CasePackagePaths {
    assets_root: PathBuf,
    case: CompleteCase,
}

impl CasePackagePaths {
    pub fn new(assets_root: impl Into<PathBuf>, case: CompleteCase) -> Self {
        Self {
            assets_root: assets_root.into(),
            case,
        }
    }

    pub fn under_default_assets_root(case: CompleteCase) -> Self {
        Self::new(DEFAULT_PACKAGE_ROOT, case)
    }

    pub fn assets_root(&self) -> &Path {
        &self.assets_root
    }

    pub fn case(&self) -> CompleteCase {
        self.case
    }

    pub fn artifact_root(&self) -> PathBuf {
        self.assets_root.join(self.case.artifact_dir_name())
    }

    pub fn review_root(&self) -> PathBuf {
        self.assets_root.join(self.case.review_dir_name())
    }

    pub fn manifest_path(&self) -> PathBuf {
        self.artifact_root().join("case-manifest.yaml")
    }

    pub fn artifact_namespace(&self) -> String {
        format!("artifact.{}", self.case.short_id())
    }

    pub fn vector_wire_path(&self, vector_id: &str) -> PathBuf {
        self.artifact_root()
            .join("vectors")
            .join(vector_id)
            .join("wire.base64")
    }

    pub fn fixture_path(&self, file_name: &str) -> PathBuf {
        self.artifact_root().join("fixtures").join(file_name)
    }

    pub fn private_fixture_path(&self, file_name: &str) -> PathBuf {
        self.artifact_root()
            .join("private-fixtures")
            .join(file_name)
    }

    pub fn binding_path(&self, family: BindingFamily, file_name: &str) -> PathBuf {
        self.artifact_root()
            .join("bindings")
            .join(family.as_dir_name())
            .join(file_name)
    }

    pub fn vector_review_path(&self, vector_id: &str) -> PathBuf {
        self.review_root()
            .join("vector-reviews")
            .join(format!("{vector_id}.yaml"))
    }

    pub fn fixture_review_path(&self, file_name: &str) -> PathBuf {
        self.review_root().join("fixture-reviews").join(file_name)
    }

    pub fn binding_review_path(&self, file_name: &str) -> PathBuf {
        self.review_root().join("binding-reviews").join(file_name)
    }

    pub fn ensure_directory_layout(&self) -> std::io::Result<()> {
        fs::create_dir_all(self.artifact_root().join("vectors"))?;
        fs::create_dir_all(self.artifact_root().join("fixtures"))?;
        fs::create_dir_all(self.artifact_root().join("private-fixtures"))?;
        for family in [
            BindingFamily::Direct,
            BindingFamily::Mechanism,
            BindingFamily::Negative,
            BindingFamily::Nested,
            BindingFamily::Routed,
        ] {
            fs::create_dir_all(
                self.artifact_root()
                    .join("bindings")
                    .join(family.as_dir_name()),
            )?;
        }

        fs::create_dir_all(self.review_root().join("vector-reviews"))?;
        fs::create_dir_all(self.review_root().join("fixture-reviews"))?;
        fs::create_dir_all(self.review_root().join("binding-reviews"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{BindingFamily, CasePackagePaths, CompleteCase};
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static TEMP_ROOT_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_root() -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let seq = TEMP_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "tsp-test-vectors-package-{}-{nanos}-{seq}",
            std::process::id()
        ))
    }

    #[test]
    fn resolves_expected_cc001_paths() {
        let paths = CasePackagePaths::new("/repo/tsp_test_vectors/assets", CompleteCase::Cc001);
        assert_eq!(
            paths.manifest_path(),
            std::path::Path::new(
                "/repo/tsp_test_vectors/assets/artifact-set.cc-001/case-manifest.yaml"
            )
        );
        assert_eq!(
            paths.vector_wire_path("BV-001"),
            std::path::Path::new(
                "/repo/tsp_test_vectors/assets/artifact-set.cc-001/vectors/BV-001/wire.base64"
            )
        );
        assert_eq!(
            paths.binding_path(BindingFamily::Direct, "request-01.yaml"),
            std::path::Path::new(
                "/repo/tsp_test_vectors/assets/artifact-set.cc-001/bindings/direct/request-01.yaml"
            )
        );
        assert_eq!(
            paths.binding_review_path("direct.request-01.yaml"),
            std::path::Path::new(
                "/repo/tsp_test_vectors/assets/review-set.cc-001/binding-reviews/direct.request-01.yaml"
            )
        );
    }

    #[test]
    fn creates_case_layout() {
        let root = temp_root();
        let paths = CasePackagePaths::new(&root, CompleteCase::Cc003);
        paths.ensure_directory_layout().unwrap();

        assert!(paths.artifact_root().is_dir());
        assert!(paths.review_root().is_dir());
        assert!(
            paths
                .binding_path(BindingFamily::Mechanism, "")
                .parent()
                .unwrap()
                .is_dir()
        );
        assert!(
            paths
                .vector_review_path("SV-001")
                .parent()
                .unwrap()
                .is_dir()
        );

        fs::remove_dir_all(root).unwrap();
    }
}
