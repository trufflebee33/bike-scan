use std::io;
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
                    }
                }
            }
        }
        transform_vec
    }

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
    pub fn calculate_length(&mut self) {
        let proposal_length: U16 =
            U16::from(8 + (self.proposal_payload.number_of_transforms as u16) * 36);
        self.proposal_payload.length = proposal_length;
        let security_association_length: U16 = proposal_length + U16::from(12);
        self.security_association_payload.sa_length = security_association_length;
        let ike_packet_length: U32 = U32::from(28) + U32::from(security_association_length);
        self.header.length = ike_packet_length;
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

#[derive(Debug, Clone, AsBytes)]
#[repr(u8)]
pub enum ExchangeType {
    IdentityProtect,
    AggressiveExchange,
    Informational,
    QuickMode,
    NewGroupMode,
}

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
