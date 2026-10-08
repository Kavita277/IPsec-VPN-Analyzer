# Person 1 Validation Report: Real StrongSwan IPsec Traffic

## Overview

This report documents the independent verification of Person 1's module against genuine, real-world IPsec/IKEv2 traffic generated between two Linux endpoints (**VM-A-Initiator** at `10.10.10.1` and **VM-B-Responder** at `10.10.10.2`) running Debian 13 (Linux kernel 6.12.107) and StrongSwan 6.0.1.

Every extracted parameter in the normalized JSON output has been independently corroborated against direct TShark dissection of the capture files.

---

## Controlled Testbed Topology

- **Initiator (VM-A)**: Debian 13 x86_64, IP `10.10.10.1`, StrongSwan 6.0.1 (charon-systemd + swanctl)
- **Responder (VM-B)**: Debian 13 x86_64, IP `10.10.10.2`, StrongSwan 6.0.1 (charon-systemd + swanctl)
- **Interconnect**: VirtualBox internal network (`intnet: ipsec_net`)
- **Packet Sniffer**: Hardware wire capture via `tcpdump -Z root -U -i any -s 0 -w <pcap> 'udp port 500 or udp port 4500'`

---

## Validation Matrix

### 1. Scenario 1 — Secure (`samples/secure/secure_01.pcap` / `analysis/secure_01.json`)

| Scenario | Field | Analyzer value | Packet/TShark value | Match |
| :--- | :--- | :--- | :--- | :--- |
| Secure | `protocol.ike_version` | `"IKEv2"` | `0x20` (IKEv2, isakmp.version) | YES |
| Secure | `session.session_id` | `"vpn_6555f95dd8e7ea73"` | Initiator SPI: `6555f95dd8e7ea73` | YES |
| Secure | `exchange_type` | `IKE_SA_INIT` (pkt 1, 2), `IKE_AUTH` (pkt 3, 4) | `34` (SA_INIT), `35` (AUTH) | YES |
| Secure | `negotiation.status` | `"successful"` | IKE_SA established & CHILD_SA negotiated | YES |
| Secure | `offered_proposals[0].encryption` | `"AES-256-CBC"` | `12` (ENCR_AES_CBC), key len `256` | YES |
| Secure | `offered_proposals[0].integrity` | `"HMAC-SHA2-256"` | `12` (AUTH_HMAC_SHA2_256_128) | YES |
| Secure | `offered_proposals[0].dh_group` | `"MODP-2048"` | `14` (MODP-2048 / Group 14) | YES |
| Secure | `negotiated_proposal.encryption` | `"AES-256-CBC"` | `12` (ENCR_AES_CBC, accepted by resp) | YES |
| Secure | `negotiated_proposal.integrity` | `"HMAC-SHA2-256"` | `12` (AUTH_HMAC_SHA2_256_128) | YES |
| Secure | `negotiated_proposal.dh_group` | `"MODP-2048"` | `14` (MODP-2048) | YES |
| Secure | `security_parameters.encryption` | `"AES-256-CBC"` | Selected in response proposal | YES |
| Secure | `security_parameters.integrity` | `"HMAC-SHA2-256"` | Selected in response proposal | YES |
| Secure | `security_parameters.dh_group` | `"MODP-2048"` | Selected in response proposal | YES |
| Secure | `security_associations` count | `4` SAs (packets 1, 2, 3, 4) | 4 packets observed | YES |
| Secure | `evidence` packet references | Packets 1, 2, 3, 4 | Verified frame numbers | YES |

---

### 2. Scenario 2 — Weak (`samples/weak/weak_01.pcap` / `analysis/weak_01.json`)

| Scenario | Field | Analyzer value | Packet/TShark value | Match |
| :--- | :--- | :--- | :--- | :--- |
| Weak | `protocol.ike_version` | `"IKEv2"` | `0x20` (IKEv2, isakmp.version) | YES |
| Weak | `session.session_id` | `"vpn_c0a15c9a873db101"` | Initiator SPI: `c0a15c9a873db101` | YES |
| Weak | `exchange_type` | `IKE_SA_INIT` (pkt 1, 2), `IKE_AUTH` (pkt 3, 4) | `34` (SA_INIT), `35` (AUTH) | YES |
| Weak | `negotiation.status` | `"successful"` | IKE_SA established & CHILD_SA negotiated | YES |
| Weak | `offered_proposals[0].encryption` | `"AES-128-CBC"` | `12` (ENCR_AES_CBC), key len `128` | YES |
| Weak | `offered_proposals[0].integrity` | `"HMAC-SHA1"` | `2` (AUTH_HMAC_SHA1_96) | YES |
| Weak | `offered_proposals[0].dh_group` | `"MODP-1024"` | `2` (MODP-1024 / Group 2) | YES |
| Weak | `negotiated_proposal.encryption` | `"AES-128-CBC"` | `12` (ENCR_AES_CBC, accepted by resp) | YES |
| Weak | `negotiated_proposal.integrity` | `"HMAC-SHA1"` | `2` (AUTH_HMAC_SHA1_96) | YES |
| Weak | `negotiated_proposal.dh_group` | `"MODP-1024"` | `2` (MODP-1024) | YES |
| Weak | `security_parameters.encryption` | `"AES-128-CBC"` | Selected in response proposal | YES |
| Weak | `security_parameters.integrity` | `"HMAC-SHA1"` | Selected in response proposal | YES |
| Weak | `security_parameters.dh_group` | `"MODP-1024"` | Selected in response proposal | YES |
| Weak | `security_associations` count | `4` SAs (packets 1, 2, 3, 4) | 4 packets observed | YES |
| Weak | `evidence` packet references | Packets 1, 2, 3, 4 | Verified frame numbers | YES |

---

### 3. Scenario 3 — Misconfigured (`samples/misconfigured/misconfigured_01.pcap` / `analysis/misconfigured_01.json`)

| Scenario | Field | Analyzer value | Packet/TShark value | Match |
| :--- | :--- | :--- | :--- | :--- |
| Misconfigured | `protocol.ike_version` | `"IKEv2"` | `0x20` (IKEv2, isakmp.version) | YES |
| Misconfigured | `session.session_id` | `"vpn_9a04b63890144d99"` | Initiator SPI: `9a04b63890144d99` | YES |
| Misconfigured | `exchange_type` | `IKE_SA_INIT` (pkt 1, 2) | `34` (IKE_SA_INIT) | YES |
| Misconfigured | `negotiation.status` | `"failed"` | Notify Error 14 (`NO_PROPOSAL_CHOSEN`) | YES |
| Misconfigured | `offered_proposals[0].encryption` | `"AES-128-CBC"` | `12` (ENCR_AES_CBC, key len 128) | YES |
| Misconfigured | `offered_proposals[0].integrity` | `"HMAC-SHA1"` | `2` (AUTH_HMAC_SHA1_96) | YES |
| Misconfigured | `offered_proposals[0].dh_group` | `"MODP-1024"` | `2` (MODP-1024) | YES |
| Misconfigured | `negotiated_proposal` | `null` | UNOBSERVABLE (no proposal chosen) | YES |
| Misconfigured | `security_parameters.encryption` | `null` | UNOBSERVABLE (negotiation failed) | YES |
| Misconfigured | `security_parameters.integrity` | `null` | UNOBSERVABLE (negotiation failed) | YES |
| Misconfigured | `security_parameters.dh_group` | `null` | UNOBSERVABLE (negotiation failed) | YES |
| Misconfigured | `security_associations` count | `2` SAs (packets 1, 2) | 2 packets observed | YES |
| Misconfigured | `evidence` notify error | `NO_PROPOSAL_CHOSEN` (pkt 2) | `isakmp.notify.msgtype == 14` | YES |

---

## Conclusion

All extracted fields from the real StrongSwan captures strictly match the independent TShark packet dissections without any guessing or invented parameters. Unobservable values remain explicitly `null`.
