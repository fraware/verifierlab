"""AttackerStateEnvelope lineage and fresh-attack qualification tests."""

from __future__ import annotations

import pytest

from verifierlab.artifacts.canonical import digest_of
from verifierlab.artifacts.cas import ContentAddressedStore
from verifierlab.execution.attacker_state import (
    AttackerStateLineage,
    append_envelope,
    assert_fresh_attack_qualification,
    make_attacker_state_envelope,
    scan_envelope_payload,
    store_envelope_payload,
    work_unit_state_binding,
)


def _fresh(**kwargs):
    base = dict(
        opaque_payload=b"fresh-state-bytes",
        strategy_identity_digest=digest_of("strategy"),
        program_identity_digest=digest_of("program"),
        attack_mode="fresh_attack",
        campaign_digest=digest_of("campaign"),
        run_digest=digest_of("run"),
        round_index=0,
        runtime_identity_digest=digest_of("runtime-a"),
        branch_id="branch-fresh",
        lineage_index=0,
        parent_state_digest=None,
    )
    base.update(kwargs)
    return make_attacker_state_envelope(**base)


def test_fresh_attack_requires_null_parent_and_new_runtime() -> None:
    envelope = _fresh()
    assert envelope.parent_state_digest is None
    assert envelope.attack_mode == "fresh_attack"
    assert_fresh_attack_qualification(envelope, inherited_parent=None)
    with pytest.raises(ValueError, match="fresh_reattack_inheritance_blocker"):
        assert_fresh_attack_qualification(envelope, inherited_parent="x" * 64)
    with pytest.raises(ValueError, match="parent_state_digest=null"):
        _fresh(parent_state_digest="a" * 64)


def test_persistent_lineage_is_append_only_with_explicit_branches(tmp_path) -> None:
    store = ContentAddressedStore(tmp_path / "store")
    payload_digest = store_envelope_payload(store, b"checkpoint-1")
    assert payload_digest

    campaign = digest_of("campaign")
    run = digest_of("run")
    lineage = AttackerStateLineage(campaign_digest=campaign, run_digest=run)
    first = make_attacker_state_envelope(
        opaque_payload=b"checkpoint-1",
        strategy_identity_digest=digest_of("strategy"),
        program_identity_digest=digest_of("program"),
        attack_mode="persistent_attack",
        campaign_digest=campaign,
        run_digest=run,
        round_index=0,
        runtime_identity_digest=digest_of("runtime"),
        branch_id="branch-a",
        lineage_index=0,
        parent_state_digest=None,
    )
    lineage = append_envelope(lineage, first)
    second = make_attacker_state_envelope(
        opaque_payload=b"checkpoint-2",
        strategy_identity_digest=digest_of("strategy"),
        program_identity_digest=digest_of("program"),
        attack_mode="persistent_attack",
        campaign_digest=campaign,
        run_digest=run,
        round_index=1,
        runtime_identity_digest=digest_of("runtime"),
        branch_id="branch-a",
        lineage_index=1,
        parent_state_digest=first.content_digest,
    )
    lineage = append_envelope(lineage, second)
    assert lineage.branch_heads["branch-a"] == second.content_digest

    # Concurrent branch without matching parent is rejected (no last-write-wins).
    stale = make_attacker_state_envelope(
        opaque_payload=b"stale",
        strategy_identity_digest=digest_of("strategy"),
        program_identity_digest=digest_of("program"),
        attack_mode="persistent_attack",
        campaign_digest=campaign,
        run_digest=run,
        round_index=2,
        runtime_identity_digest=digest_of("runtime"),
        branch_id="branch-a",
        lineage_index=2,
        parent_state_digest=first.content_digest,
    )
    with pytest.raises(ValueError, match="no last-write-wins"):
        append_envelope(lineage, stale)

    # Explicit second branch is allowed concurrently.
    other = make_attacker_state_envelope(
        opaque_payload=b"other-branch",
        strategy_identity_digest=digest_of("strategy"),
        program_identity_digest=digest_of("program"),
        attack_mode="persistent_attack",
        campaign_digest=campaign,
        run_digest=run,
        round_index=0,
        runtime_identity_digest=digest_of("runtime-b"),
        branch_id="branch-b",
        lineage_index=0,
        parent_state_digest=None,
    )
    lineage = append_envelope(lineage, other)
    assert set(lineage.branch_heads) == {"branch-a", "branch-b"}


def test_envelope_size_cap_and_forbidden_tokens() -> None:
    with pytest.raises(ValueError, match="size cap"):
        scan_envelope_payload(b"x" * (1_048_576 + 1))
    with pytest.raises(ValueError, match="forbidden token"):
        scan_envelope_payload(b"contains gt_valid marker")


def test_work_unit_binding_distinguishes_modes() -> None:
    fresh = _fresh()
    binding = work_unit_state_binding(fresh)
    assert binding["attack_mode"] == "fresh_attack"
    assert binding["parent_state_digest"] is None
    empty = work_unit_state_binding(None)
    assert empty["attacker_state_digest"] is None
