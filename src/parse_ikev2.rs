//! # Bike-Scan
//! das folgende Modul wird zum Parsen von Ike Version 2 verwendet

use zerocopy::network_endian::U128;
use zerocopy::network_endian::U16;
use zerocopy::network_endian::U32;
use zerocopy::network_endian::U64;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

use crate::ikev2::ProtocolId;

///Wrapper Struct für das Parsen des Ike Version 2 Protokolls
#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponsePacketV2 {
    ///Ike Header
    pub header: ResponseHeaderV2,
    ///Security Association Payload
    pub sa_payload_v2: ResponseSecurityAssociationV2,
    ///Proposal Payload
    pub proposal_v2: ResponseProposalV2,
    ///Verschlüsselungsalgorithmus
    pub encryption_transform: ResponseTransformV2,
    ///Pseudo-Random Funktion
    pub prf_transform: ResponseTransformV2,
    ///Integritätslagorithmus
    pub integrity_algorithm_transform: ResponseTransformV2,
    ///Diffie-Helman Gruppe
    pub diffie_transform: ResponseTransformV2,
}

impl ResponsePacketV2 {
    ///Parsen der Antwort des Servers.
    /// Die Funktion read_from_prefix liest den ersten Teil der Antwort aus.
    /// Die Länge des Wrapperstruct darf nicht größer als die Länge der
    /// gesendeten Bytes sein.
    pub fn parse_ike_v2(buf: &[u8]) -> Option<Self> {
        Self::read_from_prefix(buf)
    }
}

///Response paket with error message
#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct NotifyPacket {
    pub header: ResponseHeaderV2,
    pub notify_payload: ResponseNotifyPayloadV2,
}

impl NotifyPacket {
    pub fn parse_notify(buf: &[u8]) -> Option<Self> {
        Self::read_from_prefix(buf)
    }
}

///Ike-Header
#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponseHeaderV2 {
    ///Security Parameter Index des Initiators
    pub initiator_spi: U64,
    ///Security Parameter Index des Responder
    /// bekommt den Wert 0
    pub responder_spi: U64,
    ///nächster Payload
    pub next_payload: u8,
    ///Ike Version
    pub version: u8,
    ///Austausch Typ
    pub exchange_type: u8,
    ///Flags
    /// sind erst in der zweiten Phase notwendig
    /// und können den Wert 0 bekommen
    pub flag: u8,
    ///Nachrichten ID
    pub message_id: U32,
    ///Länge des Ike Pakets
    pub length: U32,
}

///Security Association Payload der Antwort
#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponseSecurityAssociationV2 {
    ///nächster Payload
    pub sa2_next_payload: u8,
    ///kritisches Bit
    pub critical_bit: u8,
    ///Länge des Payloads
    pub sa2_length: U16,
}

///Proposal der Antwort
#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponseProposalV2 {
    ///nächstes Proposal
    pub next_proposal: u8,
    ///reservierter Bereich
    pub reserved: u8,
    ///Länge des Proposals
    pub length: U16,
    ///Nummer des Proposals
    pub proposal_number: u8,
    ///ID des verwendeten Protokolls (IKE)
    pub protocol_id: u8,
    ///Größe des Security Parameter Indexes
    pub spi_size: u8,
    ///Anzahl der Transformationen
    pub number_of_transforms: u8,
}

///Transformation der Antwort, ohne Attribut.
/// Dieses Struct wird für den Integritätsalgortihmus,
/// die Pseudo-Random Funktion und die Diffie-Hellman Gruppe verwendet
#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponseTransformV2 {
    ///nächste Transformation
    pub next_transform: u8,
    ///reserviertere Bereich
    pub reserved: u8,
    ///Länge der Transformation
    pub length: U16,
    ///Typ der Transformation
    pub transform_type: u8,
    ///zweiter reservierter Bereich
    pub reserved2: u8,
    ///Transformations ID
    pub transform_id: U16,
}

///Transformation der Antwort mit Attribut.
/// Dieses Struct wird für das Parsen des Verschlüsselungsalgorithmus verwendet.
#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponseTransformAttributeV2 {
    ///nächste Transformation
    pub next_transform: u8,
    ///reserviertere Bereich
    pub reserved: u8,
    ///Länge der Transformation
    pub length: U16,
    ///Typ der Transformation
    pub transform_type: u8,
    ///zweiter reservierter Bereich
    pub reserved2: u8,
    ///Transformations ID
    pub transform_id: U16,
    ///Attribut für die Schlüssellänge
    pub attribute: ResponseAttributeV2,
}

///Attribut zum Verarbeiten der Schlüssellänge
#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponseAttributeV2 {
    ///Attribut Typ = Schlüssellänge
    pub attribute_type: U16,
    ///Attributwert = 128, 192 oder 256 Bit
    pub attribute_value: U16,
}

///Key Exchange Payload der Antwort
#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponseKeyExchangePayloadV2 {
    ///nächster Payload
    pub next_payload: u8,
    ///reservierter Bereich
    pub reserved: u8,
    ///Länge des Payloads
    pub length: U16,
    ///Diffie-Hellman Gruppe des Servers
    pub diffie_hellman_group: U16,
    ///Zweiter reservierter Bereich
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
    pub notify_message_type: U16,
}
