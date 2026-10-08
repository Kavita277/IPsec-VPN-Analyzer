"""IKEv2 Protocol Parser module.

Inspects structured tshark packet layers, detects IKEv2 packets,
extracts cryptographic proposals and negotiation parameters,
groups observations into VPN sessions, and generates evidence records.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from analyzer.evidence.evidence_mapper import EvidenceMapper


# IANA RFC 7296 & RFC 8247 Transform Mappings
TRANSFORM_ENCR_MAP: Dict[int, str] = {
    1: "DES-IV64",
    2: "DES",
    3: "3DES-CBC",
    4: "RC5",
    5: "IDEA",
    6: "CAST",
    7: "Blowfish",
    8: "3IDEA",
    9: "DES-IV32",
    11: "NULL",
    12: "AES-CBC",
    13: "AES-CTR",
    14: "AES-CCM-8",
    15: "AES-CCM-12",
    16: "AES-CCM-16",
    18: "AES-GCM-8",
    19: "AES-GCM-12",
    20: "AES-GCM",
    28: "CHACHA20-POLY1305",
}

TRANSFORM_INTEG_MAP: Dict[int, str] = {
    1: "HMAC-MD5",
    2: "HMAC-SHA1",
    3: "DES-MAC",
    4: "KPDK-MD5",
    5: "AES-XCBC-96",
    6: "HMAC-MD5-128",
    7: "HMAC-SHA1-160",
    8: "AES-CMAC-96",
    9: "AES-128-GMAC",
    10: "AES-192-GMAC",
    11: "AES-256-GMAC",
    12: "HMAC-SHA2-256",
    13: "HMAC-SHA2-384",
    14: "HMAC-SHA2-512",
}

TRANSFORM_DH_MAP: Dict[int, str] = {
    1: "MODP-768",
    2: "MODP-1024",
    5: "MODP-1536",
    14: "MODP-2048",
    15: "MODP-3072",
    16: "MODP-4096",
    17: "MODP-6144",
    18: "MODP-8192",
    19: "ECP-256",
    20: "ECP-384",
    21: "ECP-521",
    31: "Curve25519",
    32: "Curve448",
}

EXCHANGE_TYPE_MAP: Dict[int, str] = {
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL",
}


class IKESession:
    """Holds extracted data for a single VPN session."""

    def __init__(self, session_id: str) -> None:
        self.session_id: str = session_id
        self.ike_version: Optional[str] = None
        self.status: Optional[str] = None
        self.offered_proposals: List[Dict[str, Optional[str]]] = []
        self.negotiated_proposal: Optional[Dict[str, Optional[str]]] = None
        self.security_parameters: Dict[str, Optional[str]] = {
            "encryption": None,
            "integrity": None,
            "dh_group": None,
        }
        self.security_associations: List[Dict[str, Any]] = []


class IKEv2Parser:
    """Parses tshark JSON layers and extracts IKEv2 session parameters."""

    def __init__(self, evidence_mapper: Optional[EvidenceMapper] = None) -> None:
        self.evidence_mapper = evidence_mapper or EvidenceMapper()
        self.sessions: Dict[str, IKESession] = {}

    def parse_packet_list(self, packets: List[Dict[str, Any]]) -> Dict[str, IKESession]:
        """Parse all packets and populate sessions and evidence.
        
        Args:
            packets: List of tshark packet dicts.

        Returns:
            Dictionary of session_id -> IKESession.
        """
        for pkt in packets:
            self.parse_packet(pkt)
        return self.sessions

    def parse_packet(self, packet: Dict[str, Any]) -> Optional[IKESession]:
        """Parse an individual packet.
        
        Args:
            packet: Single packet dictionary from tshark JSON.

        Returns:
            IKESession if packet is relevant to an IKE session, None otherwise.
        """
        layers = packet.get("_source", {}).get("layers", packet.get("layers", {}))
        frame = layers.get("frame", {})
        
        # 1. Extract packet number
        packet_num_raw = frame.get("frame.number")
        packet_num: Optional[int] = None
        if packet_num_raw is not None:
            try:
                packet_num = int(packet_num_raw)
            except (ValueError, TypeError):
                packet_num = None

        # 2. Locate IKE layer (Wireshark uses 'isakmp' or 'ikev2')
        ike_layer: Optional[Dict[str, Any]] = None
        layer_prefix = ""
        for name in ("ikev2", "isakmp"):
            if name in layers:
                ike_layer = layers[name]
                layer_prefix = name
                break

        if not ike_layer or not isinstance(ike_layer, dict):
            return None

        # 3. Detect IKEv2 version
        version_str, version_field = self._detect_ike_version(ike_layer, layer_prefix)
        if version_str != "IKEv2":
            # Only process IKEv2 as per requirements
            return None

        # 4. Extract SPIs and establish session ID
        init_spi, resp_spi, spi_field = self._extract_spis(ike_layer, layer_prefix)
        if not init_spi:
            return None

        session_id = f"vpn_{init_spi.replace(':', '').lower()}"

        if session_id not in self.sessions:
            self.sessions[session_id] = IKESession(session_id)
        session = self.sessions[session_id]

        # Record IKE Version Evidence
        if not session.ike_version and version_str:
            session.ike_version = version_str
            self.evidence_mapper.record(
                packet=packet_num,
                field=version_field or f"{layer_prefix}.version",
                value=version_str,
                session_id=session_id,
            )

        # Record SPI Evidence
        if init_spi:
            self.evidence_mapper.record(
                packet=packet_num,
                field=f"{layer_prefix}.ispi" if f"{layer_prefix}.ispi" in ike_layer else f"{layer_prefix}.initiator_spi",
                value=init_spi,
                session_id=session_id,
            )
        if resp_spi and resp_spi.replace("0", "").replace(":", ""):
            self.evidence_mapper.record(
                packet=packet_num,
                field=f"{layer_prefix}.rspi" if f"{layer_prefix}.rspi" in ike_layer else f"{layer_prefix}.responder_spi",
                value=resp_spi,
                session_id=session_id,
            )

        # 5. Determine Message Flag (Request vs Response) and Exchange Type
        is_response, is_resp_field = self._is_response(ike_layer, layer_prefix)
        exchange_type, exch_field = self._extract_exchange_type(ike_layer, layer_prefix)

        # 6. Check for Notification errors (e.g. NO_PROPOSAL_CHOSEN)
        notify_error, notify_field = self._detect_notify_error(ike_layer, layer_prefix)
        if notify_error:
            session.status = "failed"
            self.evidence_mapper.record(
                packet=packet_num,
                field=notify_field or f"{layer_prefix}.notify.type",
                value=notify_error,
                session_id=session_id,
            )

        # 7. Extract Proposals and Transforms
        proposals = self._extract_proposals(ike_layer, layer_prefix, packet_num, session_id)

        if proposals:
            if not is_response:
                # Offered Proposals from initiator
                for prop in proposals:
                    # Deduplicate proposal offers
                    if prop not in session.offered_proposals:
                        session.offered_proposals.append(prop)
            else:
                # Negotiated Proposal from responder
                # In IKE_SA_INIT response, responder selects exactly one proposal
                if not session.negotiated_proposal:
                    session.negotiated_proposal = proposals[0]
                    session.status = "successful"
                    
                    # Update security_parameters
                    session.security_parameters["encryption"] = proposals[0].get("encryption")
                    session.security_parameters["integrity"] = proposals[0].get("integrity")
                    session.security_parameters["dh_group"] = proposals[0].get("dh_group")

                    self.evidence_mapper.record(
                        packet=packet_num,
                        field=f"{layer_prefix}.negotiation.status",
                        value="successful",
                        session_id=session_id,
                    )

        # 8. Record SA identifiers if observable
        sa_entry = {
            "initiator_spi": init_spi,
            "responder_spi": resp_spi if (resp_spi and resp_spi.replace("0", "").replace(":", "")) else None,
            "packet": packet_num,
        }
        if sa_entry not in session.security_associations:
            session.security_associations.append(sa_entry)

        return session

    def _detect_ike_version(
        self, layer: Dict[str, Any], prefix: str
    ) -> Tuple[Optional[str], Optional[str]]:
        """Detect if packet is IKEv2."""
        # 1. Direct version string/field
        for f_name in (f"{prefix}.version", "isakmp.version", "ikev2.version"):
            val = layer.get(f_name)
            if val is not None:
                s_val = str(val).strip()
                if s_val in ("0x20", "32", "2"):
                    return "IKEv2", f_name

        # 2. Major version tree
        version_tree = layer.get(f"{prefix}.version_tree", layer.get("isakmp.version_tree", {}))
        if isinstance(version_tree, dict):
            mjver = version_tree.get(f"{prefix}.mjver", version_tree.get("isakmp.mjver"))
            if mjver is not None and str(mjver).strip() in ("0x02", "2"):
                return "IKEv2", f"{prefix}.version_tree.{prefix}.mjver"

        # 3. If layer name is ikev2
        if prefix == "ikev2":
            return "IKEv2", "ikev2"

        return None, None

    def _extract_spis(
        self, layer: Dict[str, Any], prefix: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Extract initiator and responder SPIs."""
        init_spi: Optional[str] = None
        resp_spi: Optional[str] = None
        used_field: Optional[str] = None

        for field in (f"{prefix}.ispi", f"{prefix}.initiator_spi", "isakmp.ispi", "ikev2.initiator_spi"):
            if field in layer and layer[field] is not None:
                init_spi = str(layer[field]).strip()
                used_field = field
                break

        for field in (f"{prefix}.rspi", f"{prefix}.responder_spi", "isakmp.rspi", "ikev2.responder_spi"):
            if field in layer and layer[field] is not None:
                resp_spi = str(layer[field]).strip()
                break

        return init_spi, resp_spi, used_field

    def _is_response(self, layer: Dict[str, Any], prefix: str) -> Tuple[bool, Optional[str]]:
        """Check if packet is an IKE response or request."""
        flags_tree = layer.get(f"{prefix}.flags_tree", layer.get("isakmp.flags_tree", {}))
        if isinstance(flags_tree, dict):
            for field in (f"{prefix}.flag_r", f"{prefix}.flags.response", "isakmp.flag_r", "ikev2.flags.response"):
                if field in flags_tree:
                    return str(flags_tree[field]).strip() in ("1", "true", "True"), field

        flags = layer.get(f"{prefix}.flags", layer.get("isakmp.flags"))
        if flags is not None:
            try:
                flags_int = int(str(flags), 0)
                # Bit 5 (0x20) in IKEv2 header flags is Response
                return bool(flags_int & 0x20), f"{prefix}.flags"
            except (ValueError, TypeError):
                pass

        return False, None

    def _extract_exchange_type(
        self, layer: Dict[str, Any], prefix: str
    ) -> Tuple[Optional[str], Optional[str]]:
        """Extract exchange type (e.g. IKE_SA_INIT)."""
        for field in (f"{prefix}.exchangetype", f"{prefix}.exchange_type", "isakmp.exchangetype", "ikev2.exchange_type"):
            if field in layer and layer[field] is not None:
                raw_val = str(layer[field]).strip()
                try:
                    num_val = int(raw_val, 0)
                    return EXCHANGE_TYPE_MAP.get(num_val, raw_val), field
                except ValueError:
                    return raw_val, field
        return None, None

    def _detect_notify_error(
        self, layer: Dict[str, Any], prefix: str
    ) -> Tuple[Optional[str], Optional[str]]:
        """Detect notify payload error messages (e.g. NO_PROPOSAL_CHOSEN)."""
        # Look for notify message types in layer
        for k, v in self._flatten_dict(layer).items():
            if "notify.message_type" in k or "notify.type" in k or "notify_msg_type" in k or "notify.msgtype" in k or "msgtype" in k:
                s_val = str(v)
                if s_val == "14" or "NO_PROPOSAL_CHOSEN" in s_val.upper():
                    return "NO_PROPOSAL_CHOSEN", k
                try:
                    code = int(s_val, 0)
                    # IANA notify error status codes are 1-16383
                    if 1 <= code <= 16383:
                        return f"NOTIFY_ERROR_{code}", k
                except ValueError:
                    pass
        return None, None

    def _extract_proposals(
        self,
        layer: Dict[str, Any],
        prefix: str,
        packet_num: Optional[int],
        session_id: str,
    ) -> List[Dict[str, Optional[str]]]:
        """Extract proposals and their cryptographic transforms."""
        proposals: List[Dict[str, Optional[str]]] = []

        # Find all transform dictionaries across payload trees
        transforms_found = self._find_transforms(layer)

        if not transforms_found:
            # Check for direct proposal fields (e.g. in test fixtures or flat mocks)
            flat_proposal = self._extract_flat_proposal(layer, packet_num, session_id)
            if flat_proposal:
                return [flat_proposal]
            return []

        # Group transforms by proposal number if multiple proposals exist
        proposals_by_num: Dict[str, Dict[str, Optional[str]]] = {}

        for tf in transforms_found:
            prop_num = tf.get("prop_num", "1")
            if prop_num not in proposals_by_num:
                proposals_by_num[prop_num] = {
                    "encryption": None,
                    "integrity": None,
                    "dh_group": None,
                }
            
            p_obj = proposals_by_num[prop_num]

            if tf.get("encr"):
                p_obj["encryption"] = tf["encr"]
                self.evidence_mapper.record(
                    packet=packet_num,
                    field=tf.get("encr_field", "ikev2.transform.encryption"),
                    value=tf["encr"],
                    session_id=session_id,
                )
            if tf.get("integ"):
                p_obj["integrity"] = tf["integ"]
                self.evidence_mapper.record(
                    packet=packet_num,
                    field=tf.get("integ_field", "ikev2.transform.integrity"),
                    value=tf["integ"],
                    session_id=session_id,
                )
            if tf.get("dh"):
                p_obj["dh_group"] = tf["dh"]
                self.evidence_mapper.record(
                    packet=packet_num,
                    field=tf.get("dh_field", "ikev2.transform.dh_group"),
                    value=tf["dh"],
                    session_id=session_id,
                )

        for p_obj in proposals_by_num.values():
            if any(p_obj.values()):
                proposals.append(p_obj)

        return proposals

    def _extract_flat_proposal(
        self,
        layer: Dict[str, Any],
        packet_num: Optional[int],
        session_id: str,
    ) -> Optional[Dict[str, Optional[str]]]:
        """Extract proposal from flat mock/test structures."""
        encr = None
        integ = None
        dh = None

        for k, v in layer.items():
            if "encryption" in k and isinstance(v, str):
                encr = v
                self.evidence_mapper.record(packet_num, k, v, session_id)
            elif "integrity" in k and isinstance(v, str):
                integ = v
                self.evidence_mapper.record(packet_num, k, v, session_id)
            elif ("dh_group" in k or "dh" in k) and isinstance(v, str):
                dh = v
                self.evidence_mapper.record(packet_num, k, v, session_id)

        if encr or integ or dh:
            return {
                "encryption": encr,
                "integrity": integ,
                "dh_group": dh,
            }
        return None

    def _find_transforms(self, node: Any, current_prop: str = "1") -> List[Dict[str, Any]]:
        """Recursively scan node trees for transform structures."""
        results: List[Dict[str, Any]] = []

        if isinstance(node, dict):
            # Check if this node defines a proposal number
            for k in ("isakmp.prop.number", "ikev2.proposal.number", "prop.number"):
                if k in node:
                    current_prop = str(node[k])

            # Check if this dict represents a transform
            tf_data = self._parse_transform_node(node)
            if tf_data:
                tf_data["prop_num"] = current_prop
                results.append(tf_data)

            # Recurse into children
            for child in node.values():
                results.extend(self._find_transforms(child, current_prop))

        elif isinstance(node, list):
            for item in node:
                results.extend(self._find_transforms(item, current_prop))

        return results

    def _parse_transform_node(self, d: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse transform attributes from a dictionary node."""
        # Check transform type (1=ENCR, 2=PRF, 3=INTEG, 4=DH)
        tf_type = None
        for k in ("isakmp.tf.type", "ikev2.transform.type", "tf.type"):
            if k in d:
                try:
                    tf_type = int(str(d[k]), 0)
                except ValueError:
                    pass

        # Also check for explicit typed fields in Wireshark
        # Type 1: ENCR
        encr_val = None
        encr_field = None
        for k in ("isakmp.tf.id.encr", "ikev2.transform.encr_id", "tf.id.encr"):
            if k in d:
                encr_val, encr_field = d[k], k
                break

        # Check key length attribute if present
        key_len = None
        flat_d = self._flatten_dict(d)
        for kf, vf in flat_d.items():
            if "key_length" in kf:
                try:
                    key_len = int(str(vf), 0)
                    break
                except ValueError:
                    pass

        # Type 3: INTEG
        integ_val = None
        integ_field = None
        for k in ("isakmp.tf.id.integ", "ikev2.transform.integ_id", "tf.id.integ"):
            if k in d:
                integ_val, integ_field = d[k], k
                break

        # Type 4: DH
        dh_val = None
        dh_field = None
        for k in ("isakmp.tf.id.dh", "ikev2.transform.dh_id", "tf.id.dh", "isakmp.tf.id.group"):
            if k in d:
                dh_val, dh_field = d[k], k
                break

        # Generic transform id
        if tf_type is not None:
            for k in ("isakmp.tf.id", "ikev2.transform.id", "tf.id"):
                if k in d:
                    val = d[k]
                    if tf_type == 1 and not encr_val:
                        encr_val, encr_field = val, k
                    elif tf_type == 3 and not integ_val:
                        integ_val, integ_field = val, k
                    elif tf_type == 4 and not dh_val:
                        dh_val, dh_field = val, k

        res: Dict[str, Any] = {}
        if encr_val is not None:
            res["encr"] = self._format_encr_name(encr_val, key_len)
            res["encr_field"] = encr_field
        if integ_val is not None:
            res["integ"] = self._format_integ_name(integ_val)
            res["integ_field"] = integ_field
        if dh_val is not None:
            res["dh"] = self._format_dh_name(dh_val)
            res["dh_field"] = dh_field

        return res if res else None

    def _format_encr_name(self, raw_val: Any, key_len: Optional[int]) -> str:
        """Format encryption algorithm to standard representation."""
        s = str(raw_val).strip()
        try:
            num = int(s, 0)
            base = TRANSFORM_ENCR_MAP.get(num, s)
            if base == "AES-CBC" and key_len:
                return f"AES-{key_len}-CBC"
            elif base == "AES-GCM" and key_len:
                return f"AES-{key_len}-GCM"
            return base
        except ValueError:
            # Clean string like 'ENCR_AES_CBC (12)'
            if "AES" in s.upper():
                m = re.search(r"(\d{3})", s)
                k_len = m.group(1) if m else (str(key_len) if key_len else None)
                if "GCM" in s.upper():
                    return f"AES-{k_len}-GCM" if k_len else "AES-GCM"
                return f"AES-{k_len}-CBC" if k_len else "AES-CBC"
            elif "3DES" in s.upper():
                return "3DES-CBC"
            elif "DES" in s.upper():
                return "DES"
            return s

    def _format_integ_name(self, raw_val: Any) -> str:
        """Format integrity algorithm to standard representation."""
        s = str(raw_val).strip()
        try:
            num = int(s, 0)
            return TRANSFORM_INTEG_MAP.get(num, s)
        except ValueError:
            if "SHA2_256" in s or "SHA256" in s or "SHA-256" in s:
                return "HMAC-SHA2-256"
            elif "SHA2_384" in s or "SHA384" in s:
                return "HMAC-SHA2-384"
            elif "SHA2_512" in s or "SHA512" in s:
                return "HMAC-SHA2-512"
            elif "SHA1" in s or "SHA" in s:
                return "HMAC-SHA1"
            elif "MD5" in s:
                return "HMAC-MD5"
            return s

    def _format_dh_name(self, raw_val: Any) -> str:
        """Format DH group to standard representation."""
        s = str(raw_val).strip()
        try:
            num = int(s, 0)
            return TRANSFORM_DH_MAP.get(num, s)
        except ValueError:
            if "2048" in s or "14" in s:
                return "MODP-2048"
            elif "1024" in s or "2" in s:
                return "MODP-1024"
            elif "3072" in s or "15" in s:
                return "MODP-3072"
            elif "4096" in s or "16" in s:
                return "MODP-4096"
            elif "256" in s or "19" in s:
                return "ECP-256"
            return s

    def _flatten_dict(self, d: Dict[str, Any], parent_key: str = "", sep: str = ".") -> Dict[str, Any]:
        """Flatten nested dictionary for robust attribute search."""
        items: List[Tuple[str, Any]] = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return dict(items)
