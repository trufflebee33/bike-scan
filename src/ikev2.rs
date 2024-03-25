//Ablauf
//Exchanges
//Initiate
//CREATE_CHILD_SA
//inforamtive

//Payloads
//SA Payload
//KEy Exchange Payload
//Certificate Payload
//Certificate request payload
//Auhtnetication Payload
//Notify Payload

use zerocopy::network_endian::U16;
use zerocopy::network_endian::U32;
use zerocopy::network_endian::U64;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

//todo(header, sa payload, proposal payload, transformationen ggf. key exchange payload)
//todo: attribute der transforms definieren (dh gruppem, encryption, authentication, hash)
//todo: wrapper struct fuer ikev2 paket bauen, wrapper fuer transforms mit attributen bauen (rfc)
///Ikev2 Packet
#[derive(Debug, Copy, Clone, AsBytes)]
#[repr(packed)]
pub struct IkeV2 {
    pub header: IkeV2Header,
    //todo(sa payload, proposal payload, transforms, attribute)
}

///Ike Version 2 Header (Rfc 4306, page 42)
#[derive(Debug, Copy, Clone, AsBytes)]
#[repr(packed)]
pub struct IkeV2Header {
    pub initiator_spi: U64,
    pub responder_spi: u64,
    pub next_payload: PayloadTypeV2,
    pub version: u8,
    pub exchange_type: u8,
    pub flag: u8,
    pub message_id: u32,
    pub length: U32,
}

///Payloads Ike version 2
#[derive(Debug, Copy, Clone, AsBytes)]
#[repr(u8)]
pub enum PayloadTypeV2 {
    SecurityAssociation,
    KeyExchange,
    IdentificationInitiator,
    IdentificationResponder,
    Certificate,
    CertificateRequest,
    Authentication,
    Nonce,
    Notify,
    VendorID,
    TrafficSelectorInitiator,
    TrafficSelectorResponder,
    Encrypted,
    Configuration,
}

impl From<PayloadTypeV2> for u8 {
    fn from(value: PayloadTypeV2) -> Self {
        match value {
            PayloadTypeV2::SecurityAssociation => 33,
            PayloadTypeV2::KeyExchange => 34,
            PayloadTypeV2::IdentificationInitiator => 35,
            PayloadTypeV2::IdentificationResponder => 36,
            PayloadTypeV2::Certificate => 37,
            PayloadTypeV2::CertificateRequest => 38,
            PayloadTypeV2::Authentication => 39,
            PayloadTypeV2::Nonce => 40,
            PayloadTypeV2::Notify => 41,
            PayloadTypeV2::VendorID => 43,
            PayloadTypeV2::TrafficSelectorInitiator => 44,
            PayloadTypeV2::TrafficSelectorResponder => 45,
            PayloadTypeV2::Encrypted => 46,
            PayloadTypeV2::Configuration => 47,
        }
    }
}

impl PayloadTypeV2 {
    fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            33 => Some(PayloadTypeV2::SecurityAssociation),
            34 => Some(PayloadTypeV2::KeyExchange),
            35 => Some(PayloadTypeV2::IdentificationInitiator),
            36 => Some(PayloadTypeV2::IdentificationResponder),
            37 => Some(PayloadTypeV2::Certificate),
            38 => Some(PayloadTypeV2::CertificateRequest),
            39 => Some(PayloadTypeV2::Authentication),
            40 => Some(PayloadTypeV2::Nonce),
            41 => Some(PayloadTypeV2::Notify),
            43 => Some(PayloadTypeV2::VendorID),
            44 => Some(PayloadTypeV2::TrafficSelectorInitiator),
            45 => Some(PayloadTypeV2::TrafficSelectorResponder),
            46 => Some(PayloadTypeV2::Encrypted),
            47 => Some(PayloadTypeV2::Configuration),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, AsBytes)]
#[repr(u8)]
pub enum ExchangeTypeV2 {
    IkeSaInit,
    IkeAuth,
    CreateChildSa,
    Informational,
}

impl From<ExchangeTypeV2> for u8 {
    fn from(value: ExchangeTypeV2) -> Self {
        match value {
            ExchangeTypeV2::IkeSaInit => 34,
            ExchangeTypeV2::IkeAuth => 35,
            ExchangeTypeV2::CreateChildSa => 36,
            ExchangeTypeV2::Informational => 37,
        }
    }
}

impl ExchangeTypeV2 {
    fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            34 => Some(ExchangeTypeV2::IkeSaInit),
            35 => Some(ExchangeTypeV2::IkeAuth),
            36 => Some(ExchangeTypeV2::CreateChildSa),
            37 => Some(ExchangeTypeV2::Informational),
            _ => None,
        }
    }
}

///Payloads
///Security Association Payload for IkeV2 RFC 7296 page 77
#[derive(Debug, Copy, Clone, AsBytes)]
#[repr(packed)]
pub struct SecurityAssociationV2 {
    sa2_next_payload: PayloadTypeV2,
    critical_bit: u8,
    sa2_reserved: u8,
    sa2_length: U16,
}

///Proposal IkeV2 RFC 7296 page 80
/// next_proposal can either be 0 (no proposal after the current) or 2 (another proposal follows)
#[derive(Debug, Copy, Clone, AsBytes)]
#[repr(packed)]
pub struct Proposal {
    pub next_proposal: u8,
    pub reserved: u8,
    pub length: U16,
    pub proposal_number: u8,
    pub protocol_id: u8::from(ProtocolId),
    pub spi_size: u8,
    pub number_of_transforms: u8,
}

#[derive(Debug, Copy, Clone, AsBytes)]
#[repr(u8)]
pub enum ProtocolId {
    Reserved,
    IKE,
    AuthenticationHeader,
    EncapsulationSecurityPayload,
    FcEspHeader,
    FcCtAuthentication
}

impl From<ProtocolId> for u8 {
    fn from(value: ProtocolId) -> Self {
        match value {
            ProtocolId::Reserved => 0,
            ProtocolId::IKE => 1,
            ProtocolId::AuthenticationHeader => 2,
            ProtocolId::EncapsulationSecurityPayload => 3,
            ProtocolId::FcEspHeader => {4}
            ProtocolId::FcCtAuthentication => {5}
        }
    }
}

impl ProtocolId {
    fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(ProtocolId::Reserved),
            1 => Some(ProtocolId::IKE),
            2 => Some(ProtocolId::AuthenticationHeader),
            3 => Some(ProtocolId::EncapsulationSecurityPayload),
            4 => Some(ProtocolId::FcEspHeader),
            5 => Some(ProtocolId::FcCtAuthentication),
            _ => None,
        }
    }
}

///Transform Payload for IkeV2 Rfc 4306 page 49
pub struct TransformV2 {
    pub next_transform: u8,
    pub reserved: u8,
    pub length: U16,
    pub transform_type: u8,
    pub reserved2: u8,
    pub transform_id: u8,
}

///Key Length Attribute
#[derive(Debug, Copy, Clone, AsBytes, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct AttributeV2 {
    pub attribute_type: U16,
    pub attribute_value_or_length: U16,
}
