"""Evidence mapper module.

Tracks observable data points extracted directly from packet dissections,
mapping each observation to its packet number, original tshark field,
extracted value, and associated session ID.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class EvidenceItem:
    """Represents a single atomic observation backed by packet evidence.
    
    Attributes:
        packet: Packet number where the field was observed (or None if unobserved).
        field: Original field path/name from tshark.
        value: Extracted value as observed on the wire.
        session_id: Associated VPN session identifier.
    """
    packet: Optional[int]
    field: str
    value: Any
    session_id: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        """Convert evidence item to schema-compatible dictionary."""
        return {
            "packet": self.packet,
            "field": self.field,
            "value": self.value,
            "session_id": self.session_id,
        }


class EvidenceMapper:
    """Collects and organizes evidence records per session."""

    def __init__(self) -> None:
        self._evidence_by_session: Dict[str, List[EvidenceItem]] = {}
        self._unassociated_evidence: List[EvidenceItem] = []

    def record(
        self,
        packet: Optional[int],
        field: str,
        value: Any,
        session_id: Optional[str] = None,
    ) -> EvidenceItem:
        """Record an observable piece of evidence.
        
        Args:
            packet: Packet frame number.
            field: Exact tshark field name.
            value: Observable value.
            session_id: VPN session ID if known.

        Returns:
            The created EvidenceItem.
        """
        item = EvidenceItem(
            packet=packet,
            field=field,
            value=value,
            session_id=session_id,
        )

        if session_id:
            if session_id not in self._evidence_by_session:
                self._evidence_by_session[session_id] = []
            self._evidence_by_session[session_id].append(item)
        else:
            self._unassociated_evidence.append(item)

        return item

    def get_evidence(self, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve all evidence dictionaries for a session or globally.
        
        Args:
            session_id: Optional session identifier.

        Returns:
            List of evidence dictionaries matching the schema contract.
        """
        if session_id is not None:
            items = self._evidence_by_session.get(session_id, [])
            return [item.to_dict() for item in items]
        
        all_items: List[EvidenceItem] = []
        for items in self._evidence_by_session.values():
            all_items.extend(items)
        all_items.extend(self._unassociated_evidence)
        return [item.to_dict() for item in all_items]

    def clear(self) -> None:
        """Clear all stored evidence."""
        self._evidence_by_session.clear()
        self._unassociated_evidence.clear()
