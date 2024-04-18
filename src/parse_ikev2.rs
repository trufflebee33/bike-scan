use zerocopy::network_endian::U128;
use zerocopy::network_endian::U16;
use zerocopy::network_endian::U32;
use zerocopy::network_endian::U64;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

use crate::ikev2::ProtocolId;

#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponsePacketV2 {
    pub header: ResponseHeaderV2,
    pub sa_payload_v2: ResponseSecurityAssociationV2,
    pub proposal_v2: ResponseProposalV2,
    pub encryption_transform: ResponseTransformAttributeV2,
    pub prf_transform: ResponseTransformV2,
    pub integrity_algorithm_transform: ResponseTransformV2,
    pub diffie_transform: ResponseTransformV2,
}

impl ResponsePacketV2 {
    pub fn parse_ike_v2(buf: &[u8]) -> Option<Self> {
        Self::read_from_prefix(buf)
    }
}

#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ParsingStruct {
    pub header: ResponseHeaderV2,
    pub sa_payload_v2: ResponseSecurityAssociationV2,
    pub proposal_v2: ResponseProposalV2,
    pub encryption_transform: ResponseTransformAttributeV2,
    pub prf_transform: ResponseTransformV2,
    pub integrity_algorithm_transform: ResponseTransformV2,
    pub diffie_transform: ResponseTransformV2,
}
#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponseHeaderV2 {
    pub initiator_spi: U64,
    pub responder_spi: U64,
    pub next_payload: u8,
    pub version: u8,
    pub exchange_type: u8,
    pub flag: u8,
    pub message_id: u32,
    pub length: U32,
}

#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponseSecurityAssociationV2 {
    pub sa2_next_payload: u8,
    pub critical_bit: u8,
    pub sa2_length: U16,
}

#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponseProposalV2 {
    pub next_proposal: u8,
    pub reserved: u8,
    pub length: U16,
    pub proposal_number: u8,
    pub protocol_id: u8,
    pub spi_size: u8,
    pub number_of_transforms: u8,
}

#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponseTransformV2 {
    pub next_transform: u8,
    pub reserved: u8,
    pub length: U16,
    pub transform_type: u8,
    pub reserved2: u8,
    pub transform_id: U16,
}

#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponseTransformAttributeV2 {
    pub next_transform: u8,
    pub reserved: u8,
    pub length: U16,
    pub transform_type: u8,
    pub reserved2: u8,
    pub transform_id: U16,
    pub attribute: ResponseAttributeV2,
}

#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponseAttributeV2 {
    pub attribute_type: U16,
    pub attribute_value: U16,
}

#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponseKeyExchangePayloadV2 {
    pub next_payload: u8,
    pub reserved: u8,
    pub length: U16,
    pub diffie_hellman_group: U16,
    pub reserved2: U16,
}
///Nonce Payload (RFC 7296 Seite 99)
/// enthält die Nonce des Responders
#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponseNoncePayloadV2 {
    ///nächster Payload
    pub next_payload_: u8,
    ///reserviertes Feld
    pub reserved: u8,
    ///Payload Länge
    pub length: U16,
}
///CertificateRequest Payload (RFC 7296 Seite 95
///ist für das Anfragen präferierter Zertifikate via IKE zuständig
#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponseCertRequestV2 {
    ///nächster Payload
    pub next_payload: u8,
    ///reserviertes Feld
    pub reserved: u8,
    ///Payload Länge
    pub length: U16,
    ///Typ des Zertifikates
    pub cert_encoding: u8,
}

///Notify Payload (RFC 7296 Seite 100)
/// überträgt informative Daten wie Fehler- oder Statusmeldungen
#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponseNotifyPayloadV2 {
    ///nächster Payload
    pub next_payload: u8,
    ///reserved + critical bit
    pub reserved: u8,
    ///payload länge
    pub length: U16,
    ///Protocol Id (ist leer, wenn SPI Feld leer ist)
    pub protocol_id: u8,
    ///SPI Größe (0, wenn sich die Nachricht auf die IKE-SA bezieht)
    pub spi_size: u8,
}
