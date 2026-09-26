//! Pure fail-closed package intake admission rules.
//!
//! This module owns no transport, persistence, or build execution. It turns
//! immutable security evidence into a publication admission decision so route
//! handlers do not scatter policy checks across effectful code paths.

#![allow(clippy::needless_return)]

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntakeState {
    Received,
    Quarantined,
    Evaluated,
    PendingApproval,
    Rejected,
    Publishable,
    Published,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RiskDecision {
    Clear,
    RequireApproval,
    Reject,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalDecision {
    Approved,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DigestBindings {
    pub artifact_digest: String,
    pub source_digest: String,
    pub policy_digest: String,
    pub risk_receipt_digest: String,
    pub rebuild_receipt_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RebuildEvidence {
    pub receipt_digest: String,
    pub artifact_digest: String,
    pub source_digest: String,
    pub rebuilt_artifact_digest: String,
    pub declared_file_manifest_digest: String,
    pub dependency_lock_digest: String,
    pub matched: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RiskEvidence {
    pub artifact_digest: String,
    pub source_digest: String,
    pub policy_digest: String,
    pub risk_receipt_digest: String,
    pub decision: RiskDecision,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalEvidence {
    pub bindings: DigestBindings,
    pub decision: ApprovalDecision,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionRequest {
    pub current_state: IntakeState,
    pub artifact_digest: String,
    pub source_digest: String,
    pub policy_digest: String,
    pub rebuild: Option<RebuildEvidence>,
    pub risk: Option<RiskEvidence>,
    pub approval: Option<ApprovalEvidence>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionDecision {
    Quarantine,
    PendingApproval,
    Reject,
    Publishable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionReason {
    InvalidState,
    MissingRebuildEvidence,
    RebuildIdentityMismatch,
    RebuildArtifactMismatch,
    MissingRiskEvidence,
    RiskIdentityMismatch,
    RiskRejected,
    MissingApproval,
    ApprovalIdentityMismatch,
    ApprovalRejected,
    AllRequiredEvidenceBound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionOutcome {
    pub decision: AdmissionDecision,
    pub reason: AdmissionReason,
}

fn reject(reason: AdmissionReason) -> AdmissionOutcome {
    return AdmissionOutcome {
        decision: AdmissionDecision::Reject,
        reason,
    };
}

fn bindings_match_request(bindings: &DigestBindings, request: &AdmissionRequest) -> bool {
    return bindings.artifact_digest == request.artifact_digest
        && bindings.source_digest == request.source_digest
        && bindings.policy_digest == request.policy_digest;
}

fn rebuild_matches_request(rebuild: &RebuildEvidence, request: &AdmissionRequest) -> bool {
    return rebuild.artifact_digest == request.artifact_digest
        && rebuild.source_digest == request.source_digest;
}

fn risk_matches_request(risk: &RiskEvidence, request: &AdmissionRequest) -> bool {
    return risk.artifact_digest == request.artifact_digest
        && risk.source_digest == request.source_digest
        && risk.policy_digest == request.policy_digest;
}

pub fn evaluate(request: &AdmissionRequest) -> AdmissionOutcome {
    if !matches!(
        request.current_state,
        IntakeState::Quarantined | IntakeState::Evaluated | IntakeState::PendingApproval
    ) {
        return reject(AdmissionReason::InvalidState);
    }

    let Some(rebuild) = request.rebuild.as_ref() else {
        return AdmissionOutcome {
            decision: AdmissionDecision::Quarantine,
            reason: AdmissionReason::MissingRebuildEvidence,
        };
    };
    if !rebuild_matches_request(rebuild, request) {
        return reject(AdmissionReason::RebuildIdentityMismatch);
    }
    if !rebuild.matched || rebuild.rebuilt_artifact_digest != request.artifact_digest {
        return reject(AdmissionReason::RebuildArtifactMismatch);
    }

    let Some(risk) = request.risk.as_ref() else {
        return AdmissionOutcome {
            decision: AdmissionDecision::Quarantine,
            reason: AdmissionReason::MissingRiskEvidence,
        };
    };
    if !risk_matches_request(risk, request) {
        return reject(AdmissionReason::RiskIdentityMismatch);
    }

    match risk.decision {
        RiskDecision::Reject => {
            return reject(AdmissionReason::RiskRejected);
        }
        RiskDecision::RequireApproval => {
            let Some(approval) = request.approval.as_ref() else {
                return AdmissionOutcome {
                    decision: AdmissionDecision::PendingApproval,
                    reason: AdmissionReason::MissingApproval,
                };
            };
            if !bindings_match_request(&approval.bindings, request)
                || approval.bindings.risk_receipt_digest != risk.risk_receipt_digest
                || approval.bindings.rebuild_receipt_digest != rebuild.receipt_digest
            {
                return reject(AdmissionReason::ApprovalIdentityMismatch);
            }
            if approval.decision != ApprovalDecision::Approved {
                return reject(AdmissionReason::ApprovalRejected);
            }
            return AdmissionOutcome {
                decision: AdmissionDecision::Publishable,
                reason: AdmissionReason::AllRequiredEvidenceBound,
            };
        }
        RiskDecision::Clear => {
            return AdmissionOutcome {
                decision: AdmissionDecision::Publishable,
                reason: AdmissionReason::AllRequiredEvidenceBound,
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AdmissionDecision, AdmissionReason, AdmissionRequest, ApprovalDecision, ApprovalEvidence,
        DigestBindings, IntakeState, RebuildEvidence, RiskDecision, RiskEvidence, evaluate,
    };

    fn rebuild(artifact: &str, source: &str) -> RebuildEvidence {
        return RebuildEvidence {
            receipt_digest: "rebuild-receipt".to_owned(),
            artifact_digest: artifact.to_owned(),
            source_digest: source.to_owned(),
            rebuilt_artifact_digest: artifact.to_owned(),
            declared_file_manifest_digest: "manifest".to_owned(),
            dependency_lock_digest: "lock".to_owned(),
            matched: true,
        };
    }

    fn risk(artifact: &str, source: &str, policy: &str, decision: RiskDecision) -> RiskEvidence {
        return RiskEvidence {
            artifact_digest: artifact.to_owned(),
            source_digest: source.to_owned(),
            policy_digest: policy.to_owned(),
            risk_receipt_digest: "risk-receipt".to_owned(),
            decision,
        };
    }

    fn request(decision: RiskDecision) -> AdmissionRequest {
        let artifact = "artifact";
        let source = "source";
        let policy = "policy";
        return AdmissionRequest {
            current_state: IntakeState::Evaluated,
            artifact_digest: artifact.to_owned(),
            source_digest: source.to_owned(),
            policy_digest: policy.to_owned(),
            rebuild: Some(rebuild(artifact, source)),
            risk: Some(risk(artifact, source, policy, decision)),
            approval: None,
        };
    }

    fn approval(artifact: &str, rebuild_receipt: &str) -> ApprovalEvidence {
        return ApprovalEvidence {
            bindings: DigestBindings {
                artifact_digest: artifact.to_owned(),
                source_digest: "source".to_owned(),
                policy_digest: "policy".to_owned(),
                risk_receipt_digest: "risk-receipt".to_owned(),
                rebuild_receipt_digest: rebuild_receipt.to_owned(),
            },
            decision: ApprovalDecision::Approved,
        };
    }

    #[test]
    fn missing_security_evidence_fails_closed_to_quarantine() {
        let missing_rebuild = AdmissionRequest {
            rebuild: None,
            ..request(RiskDecision::Clear)
        };
        let rebuild_outcome = evaluate(&missing_rebuild);
        assert_eq!(rebuild_outcome.decision, AdmissionDecision::Quarantine);
        assert_eq!(
            rebuild_outcome.reason,
            AdmissionReason::MissingRebuildEvidence
        );

        let missing_risk = AdmissionRequest {
            risk: None,
            ..request(RiskDecision::Clear)
        };
        let risk_outcome = evaluate(&missing_risk);
        assert_eq!(risk_outcome.decision, AdmissionDecision::Quarantine);
        assert_eq!(risk_outcome.reason, AdmissionReason::MissingRiskEvidence);
    }

    #[test]
    fn rebuild_mismatch_rejects_publication() {
        let value = AdmissionRequest {
            rebuild: Some(RebuildEvidence {
                rebuilt_artifact_digest: "different".to_owned(),
                ..rebuild("artifact", "source")
            }),
            ..request(RiskDecision::Clear)
        };
        let outcome = evaluate(&value);
        assert_eq!(outcome.decision, AdmissionDecision::Reject);
        assert_eq!(outcome.reason, AdmissionReason::RebuildArtifactMismatch);
    }

    #[test]
    fn high_risk_finding_rejects_even_with_clean_rebuild() {
        let value = request(RiskDecision::Reject);
        let outcome = evaluate(&value);
        assert_eq!(outcome.decision, AdmissionDecision::Reject);
        assert_eq!(outcome.reason, AdmissionReason::RiskRejected);
    }

    #[test]
    fn approval_required_cannot_publish_without_digest_bound_receipt() {
        let value = request(RiskDecision::RequireApproval);
        let outcome = evaluate(&value);
        assert_eq!(outcome.decision, AdmissionDecision::PendingApproval);
        assert_eq!(outcome.reason, AdmissionReason::MissingApproval);

        let mismatched_approval = AdmissionRequest {
            approval: Some(approval("different", "rebuild-receipt")),
            ..request(RiskDecision::RequireApproval)
        };
        let mismatch_outcome = evaluate(&mismatched_approval);
        assert_eq!(mismatch_outcome.decision, AdmissionDecision::Reject);
        assert_eq!(
            mismatch_outcome.reason,
            AdmissionReason::ApprovalIdentityMismatch
        );
    }

    #[test]
    fn stale_approval_for_prior_rebuild_receipt_rejects() {
        let value = AdmissionRequest {
            approval: Some(approval("artifact", "old-rebuild-receipt")),
            ..request(RiskDecision::RequireApproval)
        };
        let outcome = evaluate(&value);
        assert_eq!(outcome.decision, AdmissionDecision::Reject);
        assert_eq!(outcome.reason, AdmissionReason::ApprovalIdentityMismatch);
    }

    #[test]
    fn matching_approval_promotes_to_publishable() {
        let value = AdmissionRequest {
            approval: Some(approval("artifact", "rebuild-receipt")),
            ..request(RiskDecision::RequireApproval)
        };
        let outcome = evaluate(&value);
        assert_eq!(outcome.decision, AdmissionDecision::Publishable);
        assert_eq!(outcome.reason, AdmissionReason::AllRequiredEvidenceBound);
    }

    #[test]
    fn received_and_terminal_states_cannot_reenter_admission() {
        for state in [
            IntakeState::Received,
            IntakeState::Published,
            IntakeState::Rejected,
        ] {
            let value = AdmissionRequest {
                current_state: state,
                ..request(RiskDecision::Clear)
            };
            let outcome = evaluate(&value);
            assert_eq!(outcome.decision, AdmissionDecision::Reject);
            assert_eq!(outcome.reason, AdmissionReason::InvalidState);
        }
    }
}
