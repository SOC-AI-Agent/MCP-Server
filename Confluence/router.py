"""
Alert name -> playbook.

Two tiers, both free: an exact match on a normalised name, then a fuzzy one for
a detection that was renamed. The notebook measured these against a hybrid
embedding retriever and found they answer a known alert name at ~0ms, which is
what almost all SOAR traffic is — an alert arrives with the name the detection
was given, and that name is in the wiki.

The third tier, dense + lexical retrieval for genuinely novel wording, is not
here. It needs an embedding model resident in memory, and it answers a question
this service is not being asked yet: matching a *question* to a playbook rather
than an alert. The shape below leaves room for it — `match` returns how it
decided, so a third tier slots in without changing the callers.

A miss is reported as a miss. A playbook that nearly matches is worse than
none: the analyst reads criteria written for a different detection and has no
way to tell.
"""

from __future__ import annotations

import difflib
import logging
import re

from playbooks import Playbook

logger = logging.getLogger("router")

# Dots and hyphens survive so T1059.001 stays one token.
_CLEAN = re.compile(r"[^a-z0-9.\- ]+")
_WS = re.compile(r"\s+")


def normalise(name: str) -> str:
    return _WS.sub(" ", _CLEAN.sub(" ", (name or "").lower())).strip()


class AlertRouter:
    """Rebuilt from the corpus on every sync; holds no state between them."""

    def __init__(self, playbooks: list[Playbook], cutoff: float = 0.85) -> None:
        self.cutoff = cutoff
        self.by_page: dict[str, Playbook] = {p.page_id: p for p in playbooks}
        self.table: dict[str, tuple[str, str, str]] = {}   # key -> (page, shown, how)
        self.conflicts: list[dict] = []

        for playbook in playbooks:
            names = [(playbook.alert_name, "alert_name")]
            names += [(a, "alias") for a in playbook.aliases]
            for name, source in names:
                key = normalise(name)
                if not key:
                    continue
                existing = self.table.get(key)
                if existing and existing[0] != playbook.page_id:
                    # A primary name outranks an alias. Two primaries claiming
                    # one name is a real ambiguity in the wiki, and it is
                    # reported rather than silently resolved — whichever page
                    # happened to load second is not an answer.
                    if source == "alert_name" and existing[2] == "alias":
                        self.table[key] = (playbook.page_id, name, source)
                    elif existing[2] == "alert_name" and source == "alias":
                        pass
                    else:
                        self.conflicts.append(
                            {"name": name, "pages": [existing[0], playbook.page_id]}
                        )
                    continue
                self.table[key] = (playbook.page_id, name, source)

        self._keys = list(self.table)
        if self.conflicts:
            for clash in self.conflicts:
                logger.warning(
                    "two playbooks claim %r: %s — one of them will never be reached",
                    clash["name"], " and ".join(clash["pages"]),
                )

    def match(self, alert_name: str) -> dict:
        """
        The playbook for this alert, with how it was found.

        `how` is returned rather than implied: a fuzzy match is a guess that
        happened to clear a threshold, and an analyst reading criteria for a
        detection with a slightly different name should be told that is what
        they are reading.
        """
        key = normalise(alert_name)
        if not key:
            return {"matched": False, "how": "empty", "playbook": None}

        hit = self.table.get(key)
        if hit:
            return {
                "matched": True, "how": "exact", "matched_name": hit[1],
                "playbook": self.by_page[hit[0]].as_dict(),
            }

        near = difflib.get_close_matches(key, self._keys, n=1, cutoff=self.cutoff)
        if near:
            page, shown, _ = self.table[near[0]]
            score = difflib.SequenceMatcher(None, key, near[0]).ratio()
            logger.info("fuzzy match %r -> %r (%.2f)", alert_name, shown, score)
            return {
                "matched": True, "how": "fuzzy", "matched_name": shown,
                "similarity": round(score, 3),
                "playbook": self.by_page[page].as_dict(),
            }

        # Said plainly. "No playbook" is a fact an analyst can act on; a
        # near-miss presented as a match is one they cannot check.
        return {
            "matched": False, "how": "miss", "playbook": None,
            "note": (
                f"No playbook covers an alert named {alert_name!r}. "
                f"{len(self.by_page)} playbook(s) are loaded; the closest was not "
                f"within the {self.cutoff} similarity cutoff."
            ),
        }

    @property
    def stats(self) -> dict:
        by_source: dict[str, int] = {}
        for _page, _shown, source in self.table.values():
            by_source[source] = by_source.get(source, 0) + 1
        return {
            "playbooks": len(self.by_page),
            "names": len(self.table),
            "by_source": by_source,
            "conflicts": self.conflicts,
        }
