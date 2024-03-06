use std::io;
use std::net::SocketAddr;

use rand::random;
use rand::Rng;
use tokio::net::UdpSocket;
use zerocopy::network_endian::U16;
use zerocopy::network_endian::U32;
use zerocopy::network_endian::U64;
use zerocopy::AsBytes;
use zerocopy::Ref;

use crate::ike::Attribute;
use crate::ike::AttributeType;
use crate::ike::AuthenticationMethod;
use crate::ike::DhGroup;
use crate::ike::EncryptionAlgorithmV1;
use crate::ike::ExchangeType;
use crate::ike::ExchangeType::IdentityProtect;
use crate::ike::HashType;
use crate::ike::IkeV1Header;
use crate::ike::PayloadTypeV1;
use crate::ike::PayloadTypeV1::NoNextPayload;
use crate::ike::PayloadTypeV1::Proposal;
use crate::ike::PayloadTypeV1::SecurityAssociation;
use crate::ike::PayloadTypeV1::Transform;
use crate::ike::ProposalPayload;
use crate::ike::SaSituation;
use crate::ike::SecurityAssociationV1;
use crate::ike::TransformPayload;

pub mod ike;
pub mod ikev2;

pub async fn connect() -> io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0".parse::<SocketAddr>().unwrap()).await?;
    let remote_addr = "192.168.122.68:500".parse::<SocketAddr>().unwrap();
    socket.connect(remote_addr).await?;
    let initiator_spi: u64 = rand::thread_rng().gen();

    println!("Initiator SPI für IkeV1: {:8x}", initiator_spi);
    let header_v1 = IkeV1Header {
        initiator_spi: U64::from(initiator_spi),
        responder_spi: 0,
        next_payload: SecurityAssociation,
        version: 16,
        exchange_type: 2,
        flag: 0,
        message_id: 0,
        length: U32::from(84),
    };
    let header_bytes = header_v1.as_bytes();
    let sa = SecurityAssociationV1 {
        sa_next_payload: NoNextPayload,
        reserved: 0,
        sa_length: U16::from(56),
        sa_doi: U32::from(1),
        sa_situation: U32::from(1),
    };
    let proposal_v1 = ProposalPayload {
        next_payload: 0,
        reserved: 0,
        length: U16::from(44),
        proposal: 1,
        protocol_id: 1,
        spi_size: 0,
        number_of_transforms: 1,
        //spi: 0,
    };
    let transform = TransformPayload {
        next_payload: 0,
        reserved: 0,
        length: U16::from(36),
        transform_number: 1,
        transform_id: 1,
        reserved2: 0,
    };
    let attribute1 = Attribute {
        attribute_type: U16::from(AttributeType::Encryption),
        attribute_value_or_length: U16::from(1),
    };
    let attribute2 = Attribute {
        attribute_type: U16::from(AttributeType::HashType),
        attribute_value_or_length: U16::from(1),
    };
    let attribute3 = Attribute {
        attribute_type: U16::from(AttributeType::AuthenticationMethod),
        attribute_value_or_length: U16::from(1),
    };
    let attribute4 = Attribute {
        attribute_type: U16::from(AttributeType::DiffieHellmanGroup),
        attribute_value_or_length: U16::from(1),
    };
    let attribute5 = Attribute {
        attribute_type: U16::from(AttributeType::LifeType),
        attribute_value_or_length: U16::from(1),
    };
    let attribute6 = Attribute {
        attribute_type: U16::from(AttributeType::LifeDuration),
        attribute_value_or_length: U16::from(4),
    };
    let life_duration_value: U64 = U64::from(2880);

    let mut send_buffer = vec![];
    send_buffer.extend_from_slice(header_bytes);
    send_buffer.extend_from_slice(sa.as_bytes());
    send_buffer.extend_from_slice(proposal_v1.as_bytes());
    send_buffer.extend_from_slice(transform.as_bytes());
    send_buffer.extend_from_slice(attribute1.as_bytes());
    send_buffer.extend_from_slice(attribute2.as_bytes());
    send_buffer.extend_from_slice(attribute3.as_bytes());
    send_buffer.extend_from_slice(attribute4.as_bytes());
    send_buffer.extend_from_slice(attribute5.as_bytes());
    send_buffer.extend_from_slice(attribute6.as_bytes());
    send_buffer.extend_from_slice(life_duration_value.as_bytes());

    let send = socket.send(&send_buffer).await?;

    println!("Sende Paket an {:?}: {:?} bytes", remote_addr, send);

    let mut buf = [0u8; 112];
    let (bytes, addr) = socket.recv_from(&mut buf).await?;
    println!("{:?} Bytes erhalten von {:?}", bytes, addr);

    Ok(())
}
