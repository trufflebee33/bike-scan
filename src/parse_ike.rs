use zerocopy::FromBytes;
use zerocopy::FromZeroes;

///todo(Ike paket bauen, reponsewrappe zum parsen benutzen)
#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponsePacket {
    pub header: ResponseHeader,
    pub sa_payload: ResponseSecurityAssociationPayload,
    pub proposal_payload: ResponseProposalPayload,
    pub transform_payload: ResponseTransformWrapped,
    pub vendor_id_payload: ResponseVendorID,
}

#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponseHeader {
    pub initiator_spi: [u64; 8],
    pub responder_spi: [u64; 8],
    pub next_payload: [u8; 1],
    pub version: [u8; 1],
    pub exchange_type: [u8; 1],
    pub flag: [u8; 1],
    pub message_id: [u32; 4],
    pub length: [u32; 4],
}
#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponseSecurityAssociationPayload {
    pub sa_next_payload: [u8; 1],
    pub reserved: [u8; 1],
    pub sa_length: [u16; 2],
    pub sa_doi: [u32; 4],
    pub sa_situation: [u32; 4],
}
#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponseProposalPayload {
    pub next_payload: [u8; 1],
    pub reserved: [u8; 1],
    pub length: [u16; 2],
    pub proposal_number: [u8; 1],
    pub protocol_id: [u8; 1],
    pub spi_size: [u8; 1],
    pub number_of_transforms: [u8; 1],
}
#[derive(Debug, Copy, Clone, FromZeroes, FromBytes)]
#[repr(packed)]
pub struct ResponseTransformWrapped {
    pub transform_payload: ResponseTransformPayload,
    pub encryption_attribute: ResponseAttribute,
    pub hash_attribute: ResponseAttribute,
    pub diffie_hellman_attribute: ResponseAttribute,
    pub authentication_method_attribute: ResponseAttribute,
    pub life_type_attribute: ResponseAttribute,
    pub life_duration_attribute: ResponseAttribute,
    pub life_duration_value: [u32; 2],
}
#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponseTransformPayload {
    pub next_payload: [u8; 1],
    pub reserved: [u8; 1],
    pub length: [u16; 2],
    pub transform_number: [u8; 1],
    pub transform_id: [u8; 1],
    pub reserved2: [u16; 2],
}
#[derive(Debug, Copy, Clone, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponseAttribute {
    pub attribute_type: [u16; 2],
    pub attribute_value_or_length: [u16; 2],
}

#[derive(Debug, Copy, Clone, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponseVendorID {
    pub next_payload: [u8; 1],
    pub reserved: [u8; 1],
    pub length: [u16; 2],
    pub vendor_id: [u16; 8],
}

///todo(notify in extra struct, weil bei fehler nur notify payload gesendet wird)
#[derive(Debug, Copy, Clone, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct RespondNotify {
    pub next_payload: [u8; 1],
    pub reserved: [u8; 1],
    pub length: [u16; 2],
    pub doi: [u64; 4],
    pub protocol_id: [u8; 1],
    pub spi_size: [u8; 1],
    pub notify_message_type: [u16; 2],
}
