//! # Bike-Scan
//! das folgende Modul erstellt ein Paket für Ike Version 1
//! Es werden die Structs für den Aufbau definiert und erläutert

use std::io;
use std::mem::size_of;

use zerocopy;
use zerocopy::network_endian::*;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

///Ike Wrapper Struct
/// dieses Struct umschließt alle Bestandteile die für ein IkeV1 Paket notwendig sind
#[derive(Debug, Clone)]
pub struct IkeV1 {
    ///der Header
    pub header: IkeV1Header,
    ///der Security Association Payload
    /// dieser enhält den Proposal- und Transform-Payload,
    /// diese werden aber als eigenständige Felder behandelt
    pub security_association_payload: SecurityAssociationV1,
    ///der Proposal Payload enthält die Transformationen, es sind maximal 255 Transformation möglich
    pub proposal_payload: ProposalPayload,
    ///der Transform Payload wird als Vektor behandelt, da so die Attribute verarbeitet werden können
    pub transform: Vec<Transform>,
}

impl IkeV1 {
    ///hier werden die Transformationen erzeugt
    /// eine Transformation besteht aus sechs Attributen
    /// 'auth_method' ist die Authentisierungsmethode
    /// 'diffie_group' ist die Diffie-Hellman Gruppe
    /// 'hash' ist der Hash-Typ
    /// 'encryption' ist der Verschlüsselungsalgorithmus
    /// 'life_type_attribute' ist die Zeiteinheit der Lebensdauer der Transformation
    /// 'life_duration_attribute' ist der Wert der Lebenszeit.
    /// Zu Beginn wird ein leerer Vektor erzeugt, in dem die Attribute, die in der For-Schleife erstellt werden, gepusht werden
    /// es gibt insgesamt 5880 Möglichkeiten, die Attribute miteinander zu kombinieren
    /// der Vektor wird am Ende der Funktion ausgegeben
    pub fn build_transforms() -> Vec<Transform> {
        let mut transform_vec = vec![];
        let payload: u8 = u8::from(PayloadTypeV1::Transform);
        for auth_method in (1..=5).chain(9..=11) {
            for diffie_group in (1..=21).chain(24..=24).chain(28..=34) {
                for hash in 1..=6 {
                    for encryption in 1..=8 {
                        transform_vec.push(Transform {
                            transform_payload: TransformPayload {
                                next_payload: payload,
                                reserved: 0,
                                length: U16::from(36),
                                transform_number: 0,
                                transform_id: 1,
                                reserved2: U16::from(0),
                            },
                            encryption_attribute: Attribute {
                                attribute_type: U16::from(AttributeType::Encryption),
                                attribute_value_or_length: U16::from(encryption),
                            },
                            hash_attribute: Attribute {
                                attribute_type: U16::from(AttributeType::HashType),
                                attribute_value_or_length: U16::from(hash),
                            },
                            diffie_hellman_attribute: Attribute {
                                attribute_type: U16::from(AttributeType::DiffieHellmanGroup),
                                attribute_value_or_length: U16::from(diffie_group),
                            },
                            authentication_method_attribute: Attribute {
                                attribute_type: U16::from(AttributeType::AuthenticationMethod),
                                attribute_value_or_length: U16::from(auth_method),
                            },
                            life_type_attribute: Attribute {
                                attribute_type: U16::from(AttributeType::LifeType),
                                attribute_value_or_length: U16::from(1),
                            },
                            life_duration_attribute: Attribute {
                                attribute_type: U16::from(AttributeType::LifeDuration),
                                attribute_value_or_length: U16::from(4),
                            },
                            life_duration_value: U32::from(28800),
                        });
                    }
                }
            }
        }
        transform_vec
    }

    /// Diese Funktion stellt sicher, dass die Anzahl der Transformationen in einem Ike Paket die Grenze von 255 nicht überschreitet.
    /// Der zweite Teil der Funktion setzt das Feld 'next_payload' der letzten Transformation auf den Wert null.
    pub fn set_transforms(&mut self, transforms: &[Transform]) {
        let length = transforms.len();
        let length_checked = u8::try_from(length).expect("Too many transforms");
        self.proposal_payload.number_of_transforms = length_checked;
        let mut change_transforms = Vec::from(transforms);
        for i in 0..length_checked {
            change_transforms[i as usize]
                .transform_payload
                .transform_number = i;
        }
        change_transforms[length - 1].transform_payload.next_payload = 0;
        self.transform = change_transforms
    }

    ///In dieser Funktion wird die Länge des Ike Pakets berechnet.
    /// Die Länge des Proposal Payloads berechnet sich aus der Größe einer Transformation multipliziert
    /// mit der Anzahl der Transformationen addiert mit der Länge des Payload Headers.
    /// Die Länge des Security Association Payloads berechnet sich aus der
    /// Länge des Proposal Payloads addiert mit der Länge des Payload Headers.
    /// Die Länge des Ike Pakets wird durch die Länge des Security Association Payload addiert mit
    /// der Länge des Headers an sich berechnet.
    pub fn calculate_length(&mut self) {
        let proposal_length: U16 =
            U16::from(8 + (self.proposal_payload.number_of_transforms as u16) * 36);
        self.proposal_payload.length = proposal_length;
        let security_association_length: U16 = proposal_length + U16::from(12);
        self.security_association_payload.sa_length = security_association_length;
        let ike_packet_length: U32 = U32::from(28) + U32::from(security_association_length);
        self.header.length = ike_packet_length;
    }

    ///Hier werden die Bestandteile des Wrapper Structs in Bytes umgewandelt und in einen Vektor gepusht
    /// die richtige Reihenfolge ist hierbei zu beachten!
    pub fn convert_to_bytes(&mut self) -> Vec<u8> {
        let mut ike_v1_bytes = vec![];
        ike_v1_bytes.extend_from_slice(self.header.as_bytes());
        ike_v1_bytes.extend_from_slice(self.security_association_payload.as_bytes());
        ike_v1_bytes.extend_from_slice(self.proposal_payload.as_bytes());
        ike_v1_bytes.extend_from_slice(self.transform.as_bytes());
        ike_v1_bytes
    }
}

///Wrapper Struct für die Transformationen.
/// Dieses Struct bildet ein Transform mit den dazugehörigen Attributen ab
#[derive(Debug, Copy, Clone, AsBytes, FromZeroes, FromBytes)]
#[repr(packed)]
pub struct Transform {
    ///Transform Payload
    pub transform_payload: TransformPayload,
    ///Attribut für den Verschlüsselungsalgorithmus
    pub encryption_attribute: Attribute,
    ///Attribut für den Hash-Typ
    pub hash_attribute: Attribute,
    ///Attribut für die Diffie-Hellman Gruppe
    pub diffie_hellman_attribute: Attribute,
    ///Attribut für die Authentisierungsmethode
    pub authentication_method_attribute: Attribute,
    ///Attribut für die Zeiteinheit der Lebensdauer
    pub life_type_attribute: Attribute,
    ///Attribut für den Wert der Lebensdauer
    pub life_duration_attribute: Attribute,
    ///Wert der Lebensdauer
    pub life_duration_value: U32,
}

///Ike Header
#[derive(Debug, Copy, Clone, AsBytes, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct IkeV1Header {
    ///Security Parameter Index des Initiators
    pub initiator_spi: U64,
    ///Security Parameter Index des Responder
    /// bekommt den Wert null
    pub responder_spi: u64,
    ///der nächste Payload (häufig Security Association Payload)
    pub next_payload: u8,
    ///die Ike Version
    pub version: u8,
    ///der Modus (eg. Main Mode, aggressive Mode)
    pub exchange_type: u8,
    ///die Flags
    /// sind erst in der zweiten Phase notwendig
    /// und können den Wert null bekommen
    pub flag: u8,
    ///erst in Phase zwei notwendig; muss den Wert null haben
    pub message_id: u32,
    ///Länge des Ike Pakets
    pub length: U32,
}

///Die Payloads für Ike Version 1
#[derive(Debug, Copy, Clone, AsBytes)]
#[repr(u8)]
pub enum PayloadTypeV1 {
    ///es folgt kein weiterer Payload
    NoNextPayload,
    ///Security Association Payload
    SecurityAssociation,
    ///Proposal Payload
    Proposal,
    ///Transformation Payload
    Transform,
    ///Key-Exchange Payload
    KeyExchange,
    ///Identifizierungs-Payload
    Identification,
    ///Certificate Payload
    Certificate,
    ///Certificate Request Payload
    CertificateRequest,
    ///Hash-Payload
    Hash,
    ///Signatur Payload
    Signature,
    ///Nonce Payload
    Nonce,
    ///Notification Payload
    Notification,
    ///Hersteller ID Payload
    VendorID,
}

impl From<PayloadTypeV1> for u8 {
    fn from(value: PayloadTypeV1) -> Self {
        match value {
            PayloadTypeV1::NoNextPayload => 0,
            PayloadTypeV1::SecurityAssociation => 1,
            PayloadTypeV1::Proposal => 2,
            PayloadTypeV1::Transform => 3,
            PayloadTypeV1::KeyExchange => 4,
            PayloadTypeV1::Identification => 5,
            PayloadTypeV1::Certificate => 6,
            PayloadTypeV1::CertificateRequest => 7,
            PayloadTypeV1::Hash => 8,
            PayloadTypeV1::Signature => 9,
            PayloadTypeV1::Nonce => 10,
            PayloadTypeV1::Notification => 11,
            PayloadTypeV1::VendorID => 13,
        }
    }
}

impl PayloadTypeV1 {
    fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(PayloadTypeV1::NoNextPayload),
            1 => Some(PayloadTypeV1::SecurityAssociation),
            2 => Some(PayloadTypeV1::Proposal),
            3 => Some(PayloadTypeV1::Transform),
            4 => Some(PayloadTypeV1::KeyExchange),
            5 => Some(PayloadTypeV1::Identification),
            6 => Some(PayloadTypeV1::Certificate),
            7 => Some(PayloadTypeV1::CertificateRequest),
            8 => Some(PayloadTypeV1::Hash),
            9 => Some(PayloadTypeV1::Signature),
            10 => Some(PayloadTypeV1::Nonce),
            11 => Some(PayloadTypeV1::Notification),
            13 => Some(PayloadTypeV1::VendorID),
            _ => None,
        }
    }
}

///Ike Version 1 Modi
#[derive(Debug, Clone, AsBytes)]
#[repr(u8)]
pub enum ExchangeType {
    ///Hauptmodus
    IdentityProtect,
    ///Aggressiver Modus
    AggressiveExchange,
    ///Informativer Modus
    Informational,
    ///Schneller Modus (Phase 2)
    QuickMode,
    ///Phase 2
    NewGroupMode,
}

///Zuweisen der Werte für den Austauschtyp
impl From<ExchangeType> for u8 {
    fn from(value: ExchangeType) -> Self {
        match value {
            ExchangeType::IdentityProtect => 2,
            ExchangeType::AggressiveExchange => 4,
            ExchangeType::Informational => 5,
            ExchangeType::QuickMode => 32,
            ExchangeType::NewGroupMode => 33,
        }
    }
}

impl ExchangeType {
    fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            2 => Some(ExchangeType::IdentityProtect),
            4 => Some(ExchangeType::AggressiveExchange),
            5 => Some(ExchangeType::Informational),
            32 => Some(ExchangeType::QuickMode),
            33 => Some(ExchangeType::NewGroupMode),
            _ => None,
        }
    }
}

///Defining Payloads
///Security Association Payload Version 1
#[derive(Debug, Copy, Clone, AsBytes, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct SecurityAssociationV1 {
    ///nächster Payload (Proposal Payload)
    pub sa_next_payload: u8,
    ///reserviertes Feld, hat Wert null
    pub reserved: u8,
    ///Länge des Payloads
    pub sa_length: U16,
    ///Domain of Interpretation
    /// hat Wert null
    pub sa_doi: U32,
    ///Situation (Varianten in Enum darunter)
    pub sa_situation: U32,
}

///Varianten der Situation
#[derive(Debug, Copy, Clone, AsBytes)]
#[repr(u8)]
pub enum SaSituation {
    ///Identifizierung der Security Association über den Identitäts-Paylod
    IdentityOnly,
    ///Security Association wird in Umgebung mit Geheimhaltung übertragen
    Secrecy,
    ///Security Association wird in einer Umgebung,
    /// die eine gelabelte Integrität erfordert, übertragen
    Integrity,
}

///Zuweisen der Werte für die Situation
impl From<SaSituation> for U32 {
    fn from(value: SaSituation) -> Self {
        match value {
            SaSituation::IdentityOnly => U32::from(1),
            SaSituation::Secrecy => U32::from(2),
            SaSituation::Integrity => U32::from(4),
        }
    }
}

impl SaSituation {
    fn try_from_u32(value: u32) -> Option<Self> {
        match value {
            1 => Some(SaSituation::IdentityOnly),
            2 => Some(SaSituation::Secrecy),
            4 => Some(SaSituation::Integrity),
            _ => None,
        }
    }
}

///Proposal Payload
#[derive(Debug, Copy, Clone, AsBytes, FromBytes, FromZeroes)]
#[repr(packed)]
///rfc 2408 page 28
pub struct ProposalPayload {
    ///nächster Payload (Transformation Payload)
    pub next_payload: u8,
    ///reserviertes Feld, hat den Wert null
    pub reserved: u8,
    ///Länge des Payloads
    pub length: U16,
    ///Nummer des aktuellen Proposals im Payload (fängt bei 1 an)
    pub proposal: u8,
    ///spezifiziert die Protokoll-ID für die aktuelle Übertragung
    /// 1 für IKE-Protokoll
    pub protocol_id: u8,
    ///Größe des Security Parameter Indexes (ist null)
    pub spi_size: u8,
    ///Anzahl der Transformationen
    pub number_of_transforms: u8,
}

/// Transform Payload  (rfc 2408 seite 30)
#[derive(Debug, Copy, Clone, AsBytes, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct TransformPayload {
    ///nächster Payload
    /// drei: Transform folgt
    /// null: letztes Transform
    pub next_payload: u8,
    ///reserviertes Feld (ist null)
    pub reserved: u8,
    ///Länge des Transforms
    pub length: U16,
    ///Nummer des Transforms
    /// fängt bei eins an
    pub transform_number: u8,
    ///legt das Protokoll fest, 1 fuer IPsec
    pub transform_id: u8,
    ///zweites reserviertes Feld (ist null)
    pub reserved2: U16,
}
///Attribute
#[derive(Debug, Copy, Clone, AsBytes, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct Attribute {
    ///Attribut Typ (wird in Enum erläutert)
    pub attribute_type: U16,
    ///Attribute value, wenn significant Bit eins ist
    /// Attribute Length, wenn significant Bit null ist, dann folgt der Wert darauf
    pub attribute_value_or_length: U16,
}

///Attribut Typen
#[derive(Debug, Copy, Clone, AsBytes)]
#[repr(u8)]
pub enum AttributeType {
    ///Verschlüsselungslagorithmus
    Encryption,
    ///Hash-Type
    HashType,
    ///Authentisierungsmethode
    AuthenticationMethod,
    ///Diffie-Hellman Gruppe
    DiffieHellmanGroup,
    ///Zeiteinheit der Lebensdauer
    LifeType,
    ///Wert der Lebensdauer
    LifeDuration,
}

/// das significant bit wird gesetzt
/// # Example
/// ```
/// 1 | 1 << 15;
/// ```
impl From<AttributeType> for U16 {
    fn from(value: AttributeType) -> Self {
        Self::new(match value {
            AttributeType::Encryption => 1 | 1 << 15,
            AttributeType::HashType => 2 | 1 << 15,
            AttributeType::AuthenticationMethod => 3 | 1 << 15,
            AttributeType::DiffieHellmanGroup => 4 | 1 << 15,
            AttributeType::LifeType => 11 | 1 << 15,
            AttributeType::LifeDuration => 12,
        })
    }
}
