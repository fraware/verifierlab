"""Campaign lifecycle states (Draft → … → Disclosure)."""

from __future__ import annotationsfrom enum import Enumclass LifecycleState(str, Enum):
    DRAFT = "draft"
    VALIDATED = "validated"
    BASELINE = "baseline"
    ATTACK = "attack"
    FREEZE = "freeze"
    LABEL_RELEASE = "label_release"
    TRIAGE = "triage"
    STATS = "stats"
    REPAIR = "repair"
    DISCLOSURE = "disclosure"


_ALLOWED: dict[LifecycleState, frozenset[LifecycleState]] = {
    LifecycleState.DRAFT: frozenset({LifecycleState.VALIDATED}),
    LifecycleState.VALIDATED: frozenset({LifecycleState.BASELINE, LifecycleState.ATTACK}),
    LifecycleState.BASELINE: frozenset({LifecycleState.ATTACK}),
    LifecycleState.ATTACK: frozenset({LifecycleState.FREEZE}),
    LifecycleState.FREEZE: frozenset({LifecycleState.LABEL_RELEASE}),
    LifecycleState.LABEL_RELEASE: frozenset(
        {LifecycleState.TRIAGE, LifecycleState.STATS, LifecycleState.REPAIR}
    ),
    LifecycleState.TRIAGE: frozenset(
        {LifecycleState.STATS, LifecycleState.REPAIR, LifecycleState.DISCLOSURE}
    ),
    LifecycleState.STATS: frozenset({LifecycleState.REPAIR, LifecycleState.DISCLOSURE}),
    LifecycleState.REPAIR: frozenset({LifecycleState.DISCLOSURE}),
    LifecycleState.DISCLOSURE: frozenset(),
}


def can_transition(current: LifecycleState | str, nxt: LifecycleState | str) -> bool:
    cur = LifecycleState(current)
    nxt_s = LifecycleState(nxt)
    return nxt_s in _ALLOWED[cur]


def assert_transition(current: LifecycleState | str, nxt: LifecycleState | str) -> None:
    if not can_transition(current, nxt):
        raise ValueError(f"illegal lifecycle transition: {current} → {nxt}")
