use zerocopy::network_endian::U16;
use zerocopy::network_endian::U32;
use zerocopy::network_endian::U64;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

use crate::ike::ExchangeType;

#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponsePacket {
    pub header: ResponseHeader,
    pub sa_payload: ResponseSecurityAssociationPayload,
    pub proposal_payload: ResponseProposalPayload,
    pub transform_payload: ResponseTransformWrapped,
    pub vendor_id_payload: ResponseVendorID,
    pub notify_payload: RespondNotify,
}

impl ResponsePacket {
    pub fn parse_response(self) {
        let diffie_hellman = self
            .transform_payload
            .diffie_hellman_attribute
            .attribute_value_or_length;
        let encryption_algorithm = self
            .transform_payload
            .encryption_attribute
            .attribute_value_or_length;
        let hash_type = self
            .transform_payload
            .hash_attribute
            .attribute_value_or_length;
        let authentication_method = self
            .transform_payload
            .authentication_method_attribute
            .attribute_value_or_length;
        let notify_message = self.notify_payload.notify_message_type;

        //save valid transforms
        let mut valid_encryption_algorithm = vec![];
        let mut valid_hash_type = vec![];
        let mut valid_diffie_hellman_group = vec![];
        let mut valid_authentication_method = vec![];
        if encryption_algorithm.get() > 0
            && hash_type.get() > 0
            && diffie_hellman.get() > 0
            && authentication_method.get() > 0
        {
            valid_encryption_algorithm.push(encryption_algorithm.get());
            valid_hash_type.push(hash_type.get());
            valid_diffie_hellman_group.push(diffie_hellman.get());
            valid_authentication_method.push(authentication_method.get());

            if !valid_encryption_algorithm.is_empty()
                && !valid_hash_type.is_empty()
                && !valid_diffie_hellman_group.is_empty()
                && !valid_authentication_method.is_empty()
            {
                //parse Ike Version
                if self.header.version == 16 {
                    println!("Ike Version is IkeV1")
                } else if self.header.version == 32 {
                    println!("Ike Version is IkeV2")
                } else {
                    println!("Invalid Version")
                }
                //Print Exchange Type
                if self.header.exchange_type == u8::from(ExchangeType::IdentityProtect) {
                    println!("Exchange Type is Main Mode")
                } else if self.header.exchange_type == u8::from(ExchangeType::AggressiveExchange) {
                    println!("Exchange Type is Aggressive Mode")
                } else {
                    println!("No valid Exchange Type")
                }
                println!("Found valid transforms: Encryption Algorithm is {:?}, Hash Type is {:?}, Diffie-Hellman-Group is {:?}, Authentication Method is {:?}", 
                         valid_encryption_algorithm, valid_hash_type, valid_diffie_hellman_group, valid_authentication_method);
            }
        }

        //Print Transforms
        if notify_message == U16::from(14) {
            println!("No valid Transform found, Error {:?}", notify_message)
        }
    }
}

///Response Wrapper Struct for Notify Message
#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponsePacketNotify {
    pub header: ResponseHeader,
    pub notify_payload: RespondNotify,
}

#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponseHeader {
    pub initiator_spi: U64,
    pub responder_spi: U64,
    pub next_payload: u8,
    pub version: u8,
    pub exchange_type: u8,
    pub flag: u8,
    pub message_id: U32,
    pub length: U32,
}
#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponseSecurityAssociationPayload {
    pub sa_next_payload: u8,
    pub reserved: u8,
    pub sa_length: U16,
    pub sa_doi: U32,
    pub sa_situation: U32,
}
#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponseProposalPayload {
    pub next_payload: u8,
    pub reserved: u8,
    pub length: U16,
    pub proposal_number: u8,
    pub protocol_id: u8,
    pub spi_size: u8,
    pub number_of_transforms: u8,
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
    pub life_duration_value: U32,
}
#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponseTransformPayload {
    pub next_payload: u8,
    pub reserved: u8,
    pub length: U16,
    pub transform_number: u8,
    pub transform_id: u8,
    pub reserved2: U16,
}
#[derive(Debug, Copy, Clone, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponseAttribute {
    pub attribute_type: U16,
    pub attribute_value_or_length: U16,
}

#[derive(Debug, Copy, Clone, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponseVendorID {
    pub next_payload: u8,
    pub reserved: u8,
    pub length: U16,
    pub vendor_id: U16,
}

///todo(notify in extra struct, weil bei fehler nur notify payload gesendet wird)
#[derive(Debug, Copy, Clone, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct RespondNotify {
    pub next_payload: u8,
    pub reserved: u8,
    pub length: U16,
    pub doi: U64,
    pub protocol_id: u8,
    pub spi_size: u8,
    pub notify_message_type: U16,
}
