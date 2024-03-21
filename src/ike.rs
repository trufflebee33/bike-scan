use std::mem::size_of;

use zerocopy;
use zerocopy::network_endian::*;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

///Ike Wrapper Struct
/// Ikev1 Packet
#[derive(Debug, Clone)]
pub struct IkeV1 {
    pub header: IkeV1Header,
    pub security_association_payload: SecurityAssociationV1,
    pub proposal_payload: ProposalPayload,
    pub transform: Vec<Transform>,
}

impl IkeV1 {
    pub fn build_transforms_calculate_length(&mut self) {
        self.proposal_payload.number_of_transforms = 0;
        let mut count_transform = 1;
        let mut payload: u8 = u8::from(PayloadTypeV1::Transform);
        for auth_method in 1..=5 {
            //for diffie_group in (1..=21).chain(24..=24).chain(28..=34) {
            for diffie_group in 1..=5 {
                for hash in 1..=2 {
                    for encryption in 1..=5 {
                        if encryption == 5 && auth_method == 5 && diffie_group == 5 && hash == 2 {
                            payload = 0;
                        }
                        self.transform.push(Transform {
                            transform_payload: TransformPayload {
                                next_payload: payload,
                                reserved: 0,
                                length: U16::from(36),
                                transform_number: count_transform,
                                transform_id: 1,
                                reserved2: 0,
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
                        self.proposal_payload.number_of_transforms += 1;
                        count_transform += 1;
                    }
                }
            }
        }
        println!(
            "{:?} Transforms generiert",
            self.proposal_payload.number_of_transforms
        );
        let proposal_length: U16 = U16::from(8) + U16::from((self.transform.len() * 36) as u16);
        println!("{:?}", proposal_length);
        self.proposal_payload.length = proposal_length;
        let security_association_length = proposal_length + U16::from(12);
        self.security_association_payload.sa_length = security_association_length;
        let ike_packet_length: U32 = U32::from(28) + U32::from(security_association_length);
        self.header.length = ike_packet_length;
        println!("header length {:?}", ike_packet_length);
    }

    //convert to bytes
    pub fn convert_to_bytes(&mut self) -> Vec<u8> {
        let mut ike_v1_bytes = vec![];
        ike_v1_bytes.extend_from_slice(self.header.as_bytes());
        ike_v1_bytes.extend_from_slice(self.security_association_payload.as_bytes());
        ike_v1_bytes.extend_from_slice(self.proposal_payload.as_bytes());
        ike_v1_bytes.extend_from_slice(self.transform.as_bytes());
        ike_v1_bytes
    }
}

///Wrapper Struct for Transforms
#[derive(Debug, Copy, Clone, AsBytes, FromZeroes, FromBytes)]
#[repr(packed)]
pub struct Transform {
    pub transform_payload: TransformPayload,
    pub encryption_attribute: Attribute,
    pub hash_attribute: Attribute,
    pub diffie_hellman_attribute: Attribute,
    pub authentication_method_attribute: Attribute,
    pub life_type_attribute: Attribute,
    pub life_duration_attribute: Attribute,
    pub life_duration_value: U32,
}

///Ikev2 Packet
#[derive(Debug, Copy, Clone, AsBytes)]
#[repr(packed)]
pub struct IkeV2 {
    pub header: IkeV2Header,
    //todo(sa payload, proposal payload, transforms, attribute)
}

///Ike Header
#[derive(Debug, Copy, Clone, AsBytes, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct IkeV1Header {
    pub initiator_spi: U64,
    pub responder_spi: u64,
    pub next_payload: u8,
    pub version: u8,
    pub exchange_type: u8,
    pub flag: u8,
    pub message_id: u32,
    pub length: U32,
}

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
#[derive(Debug, Copy, Clone, AsBytes)]
#[repr(u8)]
pub enum PayloadTypeV1 {
    NoNextPayload,
    SecurityAssociation,
    Proposal,
    Transform,
    KeyExchange,
    Identification,
    Certificate,
    CertificateRequest,
    Hash,
    Signature,
    Nonce,
    Notification,
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
pub enum ExchangeType {
    IdentityProtect,
    AggressiveExchange,
    QuickMode,
    NewGroupMode,
}

impl From<ExchangeType> for u8 {
    fn from(value: ExchangeType) -> Self {
        match value {
            ExchangeType::IdentityProtect => 2,
            ExchangeType::AggressiveExchange => 4,
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
            32 => Some(ExchangeType::QuickMode),
            33 => Some(ExchangeType::NewGroupMode),
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

///Enncryption Algorithms nach iana
#[derive(Debug, Clone, AsBytes)]
#[repr(u8)]
pub enum EncryptionAlgorithmV1 {
    DES,
    IDEA,
    Blowfish,
    Rc5,
    TrippleDES,
    Cast,
    AesCbc,
    Camellia,
}

impl From<EncryptionAlgorithmV1> for U16 {
    fn from(value: EncryptionAlgorithmV1) -> Self {
        Self::new(match value {
            EncryptionAlgorithmV1::DES => 1,
            EncryptionAlgorithmV1::IDEA => 2,
            EncryptionAlgorithmV1::Blowfish => 3,
            EncryptionAlgorithmV1::Rc5 => 4,
            EncryptionAlgorithmV1::TrippleDES => 5,
            EncryptionAlgorithmV1::Cast => 6,
            EncryptionAlgorithmV1::AesCbc => 7,
            EncryptionAlgorithmV1::Camellia => 8,
        })
    }
}

impl EncryptionAlgorithmV1 {
    fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(EncryptionAlgorithmV1::DES),
            2 => Some(EncryptionAlgorithmV1::IDEA),
            3 => Some(EncryptionAlgorithmV1::Blowfish),
            4 => Some(EncryptionAlgorithmV1::Rc5),
            5 => Some(EncryptionAlgorithmV1::TrippleDES),
            6 => Some(EncryptionAlgorithmV1::Cast),
            7 => Some(EncryptionAlgorithmV1::AesCbc),
            8 => Some(EncryptionAlgorithmV1::Camellia),
            _ => None,
        }
    }
}
//HashType
#[derive(Debug, Clone, AsBytes)]
#[repr(u8)]
pub enum HashType {
    MD5,
    SHA1,
    TIGER,
    AES128XCDC,
    SHA2_256,
    SHA2_384,
    SHA2_512,
    AES128CMAC,
    STREEBOG512,
}

impl From<HashType> for U16 {
    fn from(value: HashType) -> Self {
        Self::new(match value {
            HashType::MD5 => 1,
            HashType::SHA1 => 2,
            HashType::TIGER => 3,
            HashType::AES128XCDC => 4,
            HashType::SHA2_256 => 5,
            HashType::SHA2_384 => 6,
            HashType::SHA2_512 => 7,
            HashType::AES128CMAC => 8,
            HashType::STREEBOG512 => 9,
        })
    }
}

impl HashType {
    fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(HashType::MD5),
            2 => Some(HashType::SHA1),
            3 => Some(HashType::TIGER),
            4 => Some(HashType::AES128XCDC),
            5 => Some(HashType::SHA2_256),
            6 => Some(HashType::SHA2_384),
            7 => Some(HashType::SHA2_512),
            8 => Some(HashType::AES128CMAC),
            9 => Some(HashType::STREEBOG512),
            _ => None,
        }
    }
}

///Authentication Method
#[derive(Debug, Clone, AsBytes)]
#[repr(u8)]
pub enum AuthenticationMethod {
    PreSharedKey,
    DssSignatures,
    RsaSignatures,
    EncryptionWithRsa,
    RevisedEncryptionWithRsa,
}

impl From<AuthenticationMethod> for U16 {
    fn from(value: AuthenticationMethod) -> Self {
        Self::new(match value {
            AuthenticationMethod::PreSharedKey => 1,
            AuthenticationMethod::DssSignatures => 2,
            AuthenticationMethod::RsaSignatures => 3,
            AuthenticationMethod::EncryptionWithRsa => 4,
            AuthenticationMethod::RevisedEncryptionWithRsa => 5,
        })
    }
}

impl AuthenticationMethod {
    fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(AuthenticationMethod::PreSharedKey),
            2 => Some(AuthenticationMethod::DssSignatures),
            3 => Some(AuthenticationMethod::RsaSignatures),
            4 => Some(AuthenticationMethod::EncryptionWithRsa),
            5 => Some(AuthenticationMethod::RevisedEncryptionWithRsa),
            _ => None,
        }
    }
}

///Diffie-Hellman Gruppen vollständig
#[derive(Debug, Clone, AsBytes)]
#[repr(u8)]
pub enum DhGroup {
    MODP768bit,
    MODP1024bit,
    EC2N155,
    EC2N185,
    MODP1536bit,
    MODP2048bit,
    MODP3071bit,
    MODP4096bit,
    MODP6144bit,
    MODP8192bit,
    RandomECPGroup256bit,
    RandomECPGroup384bit,
    RandomECPGroup521bit,
    MODP2048With256bitPrimeOrder,
    BrainpoolP256r1,
    BrainpoolP384r1,
    BrainpoolP512r1,
    Curve25519,
    Curve448,
    GOST3410_2012_256,
    GOST3410_2012_512,
}

impl From<DhGroup> for U16 {
    fn from(value: DhGroup) -> Self {
        Self::new(match value {
            DhGroup::MODP768bit => 1,
            DhGroup::MODP1024bit => 2,
            DhGroup::EC2N155 => 3,
            DhGroup::EC2N185 => 4,
            DhGroup::MODP1536bit => 5,
            DhGroup::MODP2048bit => 14,
            DhGroup::MODP3071bit => 15,
            DhGroup::MODP4096bit => 16,
            DhGroup::MODP6144bit => 17,
            DhGroup::MODP8192bit => 18,
            DhGroup::RandomECPGroup256bit => 19,
            DhGroup::RandomECPGroup384bit => 20,
            DhGroup::RandomECPGroup521bit => 21,
            DhGroup::MODP2048With256bitPrimeOrder => 24,
            DhGroup::BrainpoolP256r1 => 28,
            DhGroup::BrainpoolP384r1 => 29,
            DhGroup::BrainpoolP512r1 => 30,
            DhGroup::Curve25519 => 31,
            DhGroup::Curve448 => 32,
            DhGroup::GOST3410_2012_256 => 33,
            DhGroup::GOST3410_2012_512 => 34,
        })
    }
}

impl DhGroup {
    fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(DhGroup::MODP768bit),
            2 => Some(DhGroup::MODP1024bit),
            3 => Some(DhGroup::EC2N155),
            4 => Some(DhGroup::EC2N185),
            5 => Some(DhGroup::MODP1536bit),
            14 => Some(DhGroup::MODP2048bit),
            15 => Some(DhGroup::MODP3071bit),
            16 => Some(DhGroup::MODP4096bit),
            17 => Some(DhGroup::MODP6144bit),
            18 => Some(DhGroup::MODP8192bit),
            19 => Some(DhGroup::RandomECPGroup256bit),
            20 => Some(DhGroup::RandomECPGroup384bit),
            21 => Some(DhGroup::RandomECPGroup521bit),
            24 => Some(DhGroup::MODP2048With256bitPrimeOrder),
            28 => Some(DhGroup::BrainpoolP256r1),
            29 => Some(DhGroup::BrainpoolP384r1),
            30 => Some(DhGroup::BrainpoolP512r1),
            31 => Some(DhGroup::Curve25519),
            32 => Some(DhGroup::Curve448),
            33 => Some(DhGroup::GOST3410_2012_256),
            34 => Some(DhGroup::GOST3410_2012_512),
            _ => None,
        }
    }
}

///Defining Payloads
///Security Association Payload Version 1 and 2
#[derive(Debug, Copy, Clone, AsBytes, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct SecurityAssociationV1 {
    pub sa_next_payload: u8,
    pub reserved: u8,
    pub sa_length: U16,
    pub sa_doi: U32,
    //pub sa_situation: SaSituation,
    pub sa_situation: U32,
}
#[derive(Debug, Copy, Clone, AsBytes)]
#[repr(u8)]
pub enum SaSituation {
    IdentityOnly,
    Secrecy,
    Integrity,
}

impl From<SaSituation> for u32 {
    fn from(value: SaSituation) -> Self {
        match value {
            SaSituation::IdentityOnly => 1,
            SaSituation::Secrecy => 2,
            SaSituation::Integrity => 4,
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
///Security Assocaition Payload for IkeV2 RFC 4306 page 47
#[derive(Debug, Copy, Clone, AsBytes)]
#[repr(packed)]
pub struct SecurityAssociationV2 {
    sa2_next_payload: PayloadTypeV2,
    sa2_reserved: u8,
    sa2_length: U16,
}

///Proposal Payload
#[derive(Debug, Copy, Clone, AsBytes, FromBytes, FromZeroes)]
#[repr(packed)]
///rfc 2408 page 28
pub struct ProposalPayload {
    pub next_payload: u8,
    pub reserved: u8,
    pub length: U16,
    pub proposal: u8,
    pub protocol_id: u8,
    pub spi_size: u8,
    pub number_of_transforms: u8,
    //pub spi: u32,
}

///Proposal Payload IkeV2 RFC 4306 page 48
#[derive(Debug, Copy, Clone, AsBytes)]
#[repr(packed)]
pub struct ProposalPayloadV2 {
    pub next_proposal: u8,
    pub reserved: u8,
    pub length: U16,
    pub proposal_number: u8,
    pub protocol_id: ProtocolIdV2,
    pub spi_size: u8,
    pub number_of_transforms: u8,
}
#[derive(Debug, Copy, Clone, AsBytes)]
#[repr(u8)]
pub enum ProtocolIdV2 {
    Reserved,
    IKE,
    AuthenticationHeader,
    EncapsulationSecurityPayload,
}

impl From<ProtocolIdV2> for u8 {
    fn from(value: ProtocolIdV2) -> Self {
        match value {
            ProtocolIdV2::Reserved => 0,
            ProtocolIdV2::IKE => 1,
            ProtocolIdV2::AuthenticationHeader => 2,
            ProtocolIdV2::EncapsulationSecurityPayload => 3,
        }
    }
}

impl ProtocolIdV2 {
    fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(ProtocolIdV2::Reserved),
            1 => Some(ProtocolIdV2::IKE),
            2 => Some(ProtocolIdV2::AuthenticationHeader),
            3 => Some(ProtocolIdV2::EncapsulationSecurityPayload),
            _ => None,
        }
    }
}

/// Transform Payload for IkeV1 (rfc 2408 page 30)
#[derive(Debug, Copy, Clone, AsBytes, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct TransformPayload {
    pub next_payload: u8,
    pub reserved: u8,
    pub length: U16,
    pub transform_number: u8,
    pub transform_id: u8,
    pub reserved2: u16,
}
///Attribute
#[derive(Debug, Copy, Clone, AsBytes, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct Attribute {
    pub attribute_type: U16,
    pub attribute_value_or_length: U16,
}
#[derive(Debug, Copy, Clone, AsBytes)]
#[repr(u8)]
pub enum AttributeType {
    Encryption,
    HashType,
    AuthenticationMethod,
    DiffieHellmanGroup,
    LifeType,
    LifeDuration,
}

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

///Transform Payload for IkeV2 Rfc 4306 page 49
pub struct TransformV2 {
    pub next_transform: u8,
    pub reserved: u8,
    pub length: U16,
    pub transform_type: u8,
}

///Notify Payload Ike version 1 (RFC 2408 page 39)
/// notify_message_type always with value 14 (=no proposal chosen)
#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct NotifyPayloadV1 {
    pub next_payload: u8,
    pub reserved: u8,
    pub length: u16,
    pub doi: u64,
    pub protocol_id: u8,
    pub spi_size: u8,
    pub notify_message_type: U16,
}

///VendorID Payload Ike version 1, RFC 2408 page 43
#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct VendorIDPayloadV1 {
    pub next_payload: u8,
    pub reserved: u8,
    pub length: u16,
    pub vendor_id: u16,
}
