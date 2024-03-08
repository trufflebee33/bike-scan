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
use crate::ike::AttributeType::AuthenticationMethod;
use crate::ike::AttributeType::DiffieHellmanGroup;
use crate::ike::AttributeType::Encryption;
use crate::ike::AttributeType::HashType;
use crate::ike::AttributeType::LifeDuration;
use crate::ike::AttributeType::LifeType;
use crate::ike::IkeV1;
use crate::ike::IkeV1Header;
use crate::ike::PayloadTypeV1::NoNextPayload;
use crate::ike::PayloadTypeV1::SecurityAssociation;
use crate::ike::PayloadTypeV1::Transform;
use crate::ike::ProposalPayload;
use crate::ike::SaSituation;
use crate::ike::SecurityAssociationV1;
use crate::ike::TransformPayload;

pub mod ike;
pub mod ikev2;

pub async fn scan() -> io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0".parse::<SocketAddr>().unwrap()).await?;
    let remote_addr = "192.168.122.68:500".parse::<SocketAddr>().unwrap();
    socket.connect(remote_addr).await?;

    ///calculate random Initiator Security Parameter Index
    let initiator_spi: u64 = rand::thread_rng().gen();

    println!("Initiator SPI für IkeV1: {:8x}", initiator_spi);

    //let mut send_buffer = vec![];

    ///Ike Version 1 Packet
    let mut ike_v1 = IkeV1 {
        header: IkeV1Header {
            initiator_spi: U64::from(initiator_spi),
            responder_spi: 0,
            next_payload: SecurityAssociation,
            version: 16,
            exchange_type: 2,
            flag: 0,
            message_id: 0,
            length: Default::default(),
        },
        security_association_payload: SecurityAssociationV1 {
            sa_next_payload: NoNextPayload,
            reserved: 0,
            sa_length: Default::default(),
            sa_doi: U32::from(1),
            sa_situation: U32::from(1),
        },
        proposal_payload: ProposalPayload {
            next_payload: 0,
            reserved: 0,
            length: Default::default(),
            proposal: 1,
            protocol_id: 1,
            spi_size: 0,
            number_of_transforms: 1,
        },
        transform_payload: TransformPayload {
            next_payload: 0,
            reserved: 0,
            length: Default::default(),
            transform_number: 1,
            transform_id: 1,
            reserved2: 0,
        },
        encr_attribute: Attribute {
            attribute_type: U16::from(Encryption),
            attribute_value_or_length: U16::from(2),
        },
        hash_attribute: Attribute {
            attribute_type: U16::from(HashType),
            attribute_value_or_length: U16::from(1),
        },
        diffie_hellman_attribute: Attribute {
            attribute_type: U16::from(DiffieHellmanGroup),
            attribute_value_or_length: U16::from(1),
        },
        authentication_method_attribute: Attribute {
            attribute_type: U16::from(AuthenticationMethod),
            attribute_value_or_length: U16::from(1),
        },
        life_type_attribute: Attribute {
            attribute_type: U16::from(LifeType),
            attribute_value_or_length: U16::from(1),
        },
        life_duration_attribute: Attribute {
            attribute_type: U16::from(LifeDuration),
            attribute_value_or_length: U16::from(4),
        },

        life_duration_value: U64::from(288000),
    };
    ///calculate length of Ike Version 1 Packet
    ike_v1.calculate_length();
    dbg!(std::mem::size_of::<IkeV1>());
    ///send Ike Version 1 Packet
    //let send = socket.send(&send_buffer).await?;
    let ike_bytes = ike_v1.as_bytes();
    let send_ike_v1 = socket.send(&ike_bytes).await;

    println!(
        "Sende Wrapper Paket an {:?}: {:?} bytes",
        remote_addr, send_ike_v1
    );

    ///Receive Answer from Ipsec-Server
    let mut buf = [0u8; 112];
    let (bytes, addr) = socket.recv_from(&mut buf).await?;
    println!("{:?} Bytes erhalten von {:?}", bytes, addr);

    Ok(())
}
