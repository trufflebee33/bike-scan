use zerocopy::network_endian::U128;
use zerocopy::network_endian::U16;
use zerocopy::network_endian::U32;
use zerocopy::network_endian::U64;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

//done(header, sa payload, proposal payload, transformationen ggf. key exchange payload)
//todo: attribute der transforms definieren (dh gruppem, encryption, authentication, hash)
//todo: wrapper struct fuer ikev2 paket bauen, wrapper fuer transforms mit attributen bauen (rfc)
///Ikev2 Packet
#[derive(Debug, Clone)]
pub struct IkeV2 {
    pub header: IkeV2Header,
    pub sa_payload_v2: SecurityAssociationV2,
    pub proposal_v2: Proposal,
    pub encryption_transforms: Vec<TransformAttributeV2>,
    pub prf_transform: Vec<TransformV2>,
    pub integrity_algorithm_transform: Vec<TransformV2>,
    pub diffie_transform: Vec<TransformV2>,
    pub key_exchange: KeyExchangePayloadV2,
    pub key_exchange_date: U128,
    pub nonce_payload: NoncePayloadV2,
    pub nonce_data: U64,
}
//todo(Attribute impln)
impl IkeV2 {
    pub fn build_transforms_v2() -> (
        Vec<TransformAttributeV2>,
        Vec<TransformV2>,
        Vec<TransformV2>,
        Vec<TransformV2>,
    ) {
        let mut transform_vec_encryption: Vec<TransformAttributeV2> = vec![];
        let mut transform_vec_prf: Vec<TransformV2> = vec![];
        let mut transform_vec_integrity_algorithm: Vec<TransformV2> = vec![];
        let mut transform_vec_diffie_group: Vec<TransformV2> = vec![];
        for encryption_v2 in (1u16..=9).chain(11..=16).chain(18..=35) {
            if encryption_v2 == 12 || encryption_v2 == 13 {
                for attribute_value in [128, 192, 256] {
                    transform_vec_encryption.push(TransformAttributeV2 {
                        next_transform: 3,
                        reserved: 0,
                        length: Default::default(),
                        transform_type: u8::from(TransformTypeValues::EncryptionAlgorithm),
                        reserved2: 0,
                        transform_id: U16::from(encryption_v2),
                        attribute: AttributeV2 {
                            attribute_type: U16::from(AttributeType::KeyLength),
                            attribute_value: U16::from(attribute_value),
                        },
                    });
                }
            } else {
                transform_vec_encryption.push(TransformAttributeV2 {
                    next_transform: 3,
                    reserved: 0,
                    length: Default::default(),
                    transform_type: u8::from(TransformTypeValues::EncryptionAlgorithm),
                    reserved2: 0,
                    transform_id: U16::from(encryption_v2),
                    attribute: AttributeV2 {
                        attribute_type: U16::from(AttributeType::KeyLength),
                        attribute_value: U16::from(0),
                    },
                })
            }
        }
        for prf_value in 1u16..=9 {
            transform_vec_prf.push(TransformV2 {
                next_transform: 3,
                reserved: 0,
                length: Default::default(),
                transform_type: u8::from(TransformTypeValues::PseudoRandomFunction),
                reserved2: 0,
                transform_id: U16::from(prf_value),
            })
        }
        for integrity_algorithm in 1u16..=14 {
            transform_vec_integrity_algorithm.push(TransformV2 {
                next_transform: 3,
                reserved: 0,
                length: Default::default(),
                transform_type: u8::from(TransformTypeValues::IntegrityAlgorithm),
                reserved2: 0,
                transform_id: U16::from(integrity_algorithm),
            })
        }
        for diffie_group in (1u16..=2).chain(5..=5).chain(14..=34) {
            transform_vec_diffie_group.push(TransformV2 {
                next_transform: 3,
                reserved: 0,
                length: Default::default(),
                transform_type: u8::from(TransformTypeValues::DiffieHellmanGroup),
                reserved2: 0,
                transform_id: U16::from(diffie_group),
            })
        }
        (
            transform_vec_encryption,
            transform_vec_prf,
            transform_vec_integrity_algorithm,
            transform_vec_diffie_group,
        )
    }

    pub fn set_transforms_v2(
        &mut self,
        encryption: &[TransformAttributeV2],
        prf: &[TransformV2],
        integrity_algorithm: &[TransformV2],
        diffie_group: &[TransformV2],
    ) {
        let full_length =
            encryption.len() + prf.len() + integrity_algorithm.len() + diffie_group.len();
        let length_checked = u8::try_from(full_length).expect("Too many transforms");
        self.proposal_v2.number_of_transforms = length_checked;
        self.encryption_transforms = Vec::from(encryption);
        self.prf_transform = Vec::from(prf);
        self.integrity_algorithm_transform = Vec::from(integrity_algorithm);
        let mut change_transform = Vec::from(diffie_group);
        change_transform[diffie_group.len() - 1].next_transform =
            u8::from(PayloadTypeV2::KeyExchange);
        self.diffie_transform = change_transform
    }

    pub fn calculate_length_v2(&mut self) {
        let mut length = U16::from(0);
        for encr in &mut self.encryption_transforms {
            encr.calculate_length();
            length += encr.length
        }
        for prf in &mut self.prf_transform {
            prf.calculate_length();
            length += prf.length
        }
        for integ_alg in &mut self.integrity_algorithm_transform {
            integ_alg.calculate_length();
            length += integ_alg.length
        }
        for diffie in &mut self.diffie_transform {
            diffie.calculate_length();
            length += diffie.length;
        }
        println!("{:?}", length);
        println!("ecnryption length {}", self.encryption_transforms.len());
        let proposal_length = U16::from(8) + length;
        self.proposal_v2.length = proposal_length;
        println!("proposal length is {:?}", proposal_length);
        let sa_length = proposal_length;
        self.sa_payload_v2.sa2_length = sa_length;
        println!("Sa length is {:?}", sa_length);
        self.key_exchange.length = U16::from(8);
        self.nonce_payload.length = U16::from(24);
        self.header.length = U32::from(28) + U32::from(sa_length);
        println!("Packet length is {:?}", self.header.length);
    }

    pub fn convert_to_bytes_v2(&mut self) -> Vec<u8> {
        let mut bytes_v2 = vec![];
        bytes_v2.extend_from_slice(self.header.as_bytes());
        bytes_v2.extend_from_slice(self.sa_payload_v2.as_bytes());
        bytes_v2.extend_from_slice(self.proposal_v2.as_bytes());
        bytes_v2.extend_from_slice(self.encryption_transforms.as_bytes());
        bytes_v2.extend_from_slice(self.prf_transform.as_bytes());
        bytes_v2.extend_from_slice(self.integrity_algorithm_transform.as_bytes());
        bytes_v2.extend_from_slice(self.diffie_transform.as_bytes());
        bytes_v2.extend_from_slice(self.key_exchange.as_bytes());
        bytes_v2.extend_from_slice(self.key_exchange_date.as_bytes());
        bytes_v2.extend_from_slice(self.nonce_payload.as_bytes());
        bytes_v2.extend_from_slice(self.nonce_data.as_bytes());
        bytes_v2
    }
}

///Ike Version 2 Header (Rfc 4306, page 42)
#[derive(Debug, Copy, Clone, AsBytes)]
#[repr(packed)]
pub struct IkeV2Header {
    pub initiator_spi: U64,
    pub responder_spi: u64,
    pub next_payload: u8,
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
    NoNextPayload,
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
            PayloadTypeV2::NoNextPayload => 0,
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
            0 => Some(PayloadTypeV2::NoNextPayload),
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
    pub sa2_next_payload: u8,
    pub critical_bit: u8,
    pub sa2_length: U16,
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
    pub protocol_id: ProtocolId,
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
    FcCtAuthentication,
}

impl From<ProtocolId> for u8 {
    fn from(value: ProtocolId) -> Self {
        match value {
            ProtocolId::Reserved => 0,
            ProtocolId::IKE => 1,
            ProtocolId::AuthenticationHeader => 2,
            ProtocolId::EncapsulationSecurityPayload => 3,
            ProtocolId::FcEspHeader => 4,
            ProtocolId::FcCtAuthentication => 5,
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

///Transform Payload for IkeV2 Rfc 7296 page 79
#[derive(Debug, Copy, Clone, AsBytes, PartialEq)]
#[repr(packed)]
pub struct TransformV2 {
    pub next_transform: u8,
    pub reserved: u8,
    pub length: U16,
    pub transform_type: u8,
    pub reserved2: u8,
    pub transform_id: U16,
}

impl TransformV2 {
    pub fn calculate_length(&mut self) {
        self.length = U16::from(8);
    }
}

///Wrapper struct for transforms
#[derive(Debug, Copy, Clone, AsBytes, PartialEq)]
#[repr(packed)]
pub struct TransformAttributeV2 {
    pub next_transform: u8,
    pub reserved: u8,
    pub length: U16,
    pub transform_type: u8,
    pub reserved2: u8,
    pub transform_id: U16,
    pub attribute: AttributeV2,
}

impl TransformAttributeV2 {
    pub fn calculate_length(&mut self) {
        self.length = U16::from(4 + 8);
    }
}

///Key Length Attribute
#[derive(Debug, Copy, Clone, AsBytes, FromBytes, FromZeroes, PartialEq)]
#[repr(packed)]
pub struct AttributeV2 {
    pub attribute_type: U16,
    pub attribute_value: U16,
}

#[derive(Debug, Copy, Clone, AsBytes)]
#[repr(u8)]
pub enum AttributeType {
    KeyLength,
}

impl From<AttributeType> for U16 {
    fn from(value: AttributeType) -> Self {
        Self::new(match value {
            AttributeType::KeyLength => 14 | 1 << 15,
        })
    }
}

///key length of AES_CBC and AES_CTR
#[derive(Debug, Copy, Clone, AsBytes)]
#[repr(u8)]
pub enum AttributeValue {
    Bit128,
    Bit192,
    Bit256,
}

impl From<AttributeValue> for U16 {
    fn from(value: AttributeValue) -> Self {
        Self::new(match value {
            AttributeValue::Bit128 => 10,
            AttributeValue::Bit192 => 12,
            AttributeValue::Bit256 => 14,
        })
    }
}

///Defining Transform Types and IDs
/// Transform Type Values
#[derive(Debug, Copy, Clone, AsBytes)]
#[repr(u8)]
pub enum TransformTypeValues {
    EncryptionAlgorithm,
    PseudoRandomFunction,
    IntegrityAlgorithm,
    DiffieHellmanGroup,
    ExtendedSequenceNumbers,
}

impl From<TransformTypeValues> for u8 {
    fn from(value: TransformTypeValues) -> Self {
        match value {
            TransformTypeValues::EncryptionAlgorithm => 1,
            TransformTypeValues::PseudoRandomFunction => 2,
            TransformTypeValues::IntegrityAlgorithm => 3,
            TransformTypeValues::DiffieHellmanGroup => 4,
            TransformTypeValues::ExtendedSequenceNumbers => 5,
        }
    }
}

///Key Exchange Payload RFC page 89
#[derive(Debug, Copy, Clone, AsBytes, FromBytes, FromZeroes, PartialEq)]
#[repr(packed)]
pub struct KeyExchangePayloadV2 {
    pub next_payload: u8,
    pub critical_bit: u8,
    pub reserved: u8,
    pub length: U16,
    pub diffie_hellman_group: U32,
    pub reserved2: U32,
}
///Nonce Payload RFC 7296 page 99
#[derive(Debug, Copy, Clone, AsBytes, FromBytes, FromZeroes, PartialEq)]
#[repr(packed)]
pub struct NoncePayloadV2 {
    pub next_payload_: u8,
    pub critical_bit: u8,
    pub reserved: u8,
    pub length: U16,
}
