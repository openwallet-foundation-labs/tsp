//! Planned home for test-vector authoring and asset-freezing logic.
//!
//! SDK-backed candidate generation is now exposed only through test-only helper
//! surfaces in `tsp_sdk`, while the canonical authoring path lives here.

pub mod candidate;
pub mod check;
pub mod freeze;
pub mod generate;
pub mod package;
pub mod source;
pub mod writer;

pub use candidate::{
    CandidateIdentity, CiphertextFamilyCandidate, DigestMismatchCandidate, DirectAcceptCandidate,
    DirectMessageCandidate, DirectRequestCandidate, DirectRfdCandidate, NestedAcceptCandidate,
    NestedMessageCandidate, NestedRequestCandidate, NestedWithoutOuterCandidate,
    NoPriorRelationshipCandidate, NonConfidentialBindingCandidate, RoutedAcceptCandidate,
    RoutedMessageCandidate, RoutedPathCandidate, RoutedRequestCandidate,
    SenderFieldMechanismCandidate,
};
pub use check::{
    check_ciphertext_family_candidate, check_digest_mismatch_candidate,
    check_direct_accept_candidate, check_direct_message_candidate, check_direct_request_candidate,
    check_direct_rfd_candidate, check_nested_accept_candidate, check_nested_message_candidate,
    check_nested_request_candidate, check_nested_without_outer_candidate,
    check_no_prior_relationship_candidate, check_nonconfidential_binding_candidate,
    check_routed_accept_candidate, check_routed_message_candidate, check_routed_path_candidate,
    check_routed_request_candidate, check_sender_field_mechanism_candidate,
};
pub use freeze::{
    FreezeResult, freeze_ciphertext_family_from_source, freeze_digest_mismatch_from_source,
    freeze_direct_accept_from_source, freeze_direct_message_from_source,
    freeze_direct_request_from_source, freeze_direct_rfd_from_source,
    freeze_nested_accept_from_source, freeze_nested_message_from_source,
    freeze_nested_request_from_source, freeze_nested_without_outer_from_source,
    freeze_no_prior_relationship_from_source, freeze_nonconfidential_binding_from_source,
    freeze_routed_accept_from_source, freeze_routed_message_from_source,
    freeze_routed_path_from_source, freeze_routed_request_from_source,
    freeze_sender_field_mechanism_from_source,
};
pub use generate::{
    GenerateCaseRequest, GenerateVectorRequest, generate_case_package, generate_vector_asset_set,
};
pub use package::{BindingFamily, CasePackagePaths, CompleteCase};
pub use source::{
    CandidateProvenance, CandidateSourceKind, CandidateSourceMetadata, CaseVectorRequest,
    DirectControlSource, MessageSource, NegativeDerivationSource, NestedControlSource,
    NestedWithoutOuterRequest, NoPriorRelationshipRequest, RoutedControlSource, SdkCandidateSource,
    SourcedCandidate, SpecCandidateSource,
};
pub use writer::{
    BindingReviewRecord, ConversationFixtureRecord, FixtureReviewRecord, PackageWriter,
    VectorReviewRecord, write_ciphertext_family_candidate, write_digest_mismatch_candidate,
    write_direct_accept_candidate, write_direct_message_candidate, write_direct_request_candidate,
    write_direct_rfd_candidate, write_nested_accept_candidate, write_nested_message_candidate,
    write_nested_request_candidate, write_nested_without_outer_candidate,
    write_no_prior_relationship_candidate, write_nonconfidential_binding_candidate,
    write_routed_accept_candidate, write_routed_message_candidate, write_routed_path_candidate,
    write_routed_request_candidate, write_sender_field_mechanism_candidate,
};
