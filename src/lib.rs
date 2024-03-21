use std::io;
use std::net::SocketAddr;

use rand::random;
use rand::Rng;
use tokio::net::UdpSocket;
use zerocopy::network_endian::U16;
use zerocopy::network_endian::U32;
use zerocopy::network_endian::U64;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

use crate::ike::Attribute;
use crate::ike::IkeV1;
use crate::ike::IkeV1Header;
use crate::ike::NotifyPayloadV1;
use crate::ike::PayloadTypeV1::NoNextPayload;
use crate::ike::PayloadTypeV1::SecurityAssociation;
use crate::ike::ProposalPayload;
use crate::ike::SecurityAssociationV1;
use crate::ike::Transform;
use crate::ike::TransformPayload;
use crate::ike::VendorIDPayloadV1;
use crate::parse_ike::ResponseAttribute;
use crate::parse_ike::ResponsePacket;

pub mod ike;
pub mod ikev2;
pub mod parse_ike;

pub async fn scan() -> io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0".parse::<SocketAddr>().unwrap()).await?;
    let remote_addr = "192.168.122.68:500".parse::<SocketAddr>().unwrap();
    socket.connect(remote_addr).await?;

    //calculate random Initiator Security Parameter Index
    let initiator_spi: u64 = rand::thread_rng().gen();

    println!("Initiator SPI für IkeV1: {:8x}", initiator_spi);

    //Ike Version 1 Packet
    let mut ike_v1 = IkeV1 {
        header: IkeV1Header {
            initiator_spi: U64::from(initiator_spi),
            responder_spi: 0,
            next_payload: u8::from(SecurityAssociation),
            version: 16,
            exchange_type: 2,
            flag: 0,
            message_id: 0,
            length: Default::default(),
        },
        security_association_payload: SecurityAssociationV1 {
            sa_next_payload: u8::from(NoNextPayload),
            reserved: 0,
            sa_length: Default::default(),
            sa_doi: U32::from(1),
            sa_situation: U32::from(1),
        },
        proposal_payload: ProposalPayload {
            next_payload: u8::from(NoNextPayload),
            reserved: 0,
            length: Default::default(),
            proposal: 1,
            protocol_id: 1,
            spi_size: 0,
            number_of_transforms: Default::default(),
        },
        transform: vec![],
    };
    ike_v1.build_transforms_calculate_length();
    let bytes = ike_v1.convert_to_bytes();
    //let mut test = ike_v1.transform_payload.transform_number;
    //println!("Transform Payload {:?}", ike_v1.transform_payload);
    dbg!(std::mem::size_of::<ResponsePacket>());

    let send_ike_v1 = socket.send(&bytes).await;

    println!(
        "Sende Wrapper Paket an {:?}: {:?} bytes",
        remote_addr, send_ike_v1
    );

    let mut buf = [0u8; 112];
    let (bytes, addr) = socket
        .recv_from(&mut buf)
        .await
        .expect("couldn't read buffer");
    println!("{:?} Bytes erhalten von {:?}", bytes, addr);

    let byte_slice = buf.as_slice();
    println!("{:?}", byte_slice);

    let ike_response = ResponsePacket::read_from_prefix(byte_slice).expect("Slice too short");
    println!("Response: {:?}", ike_response);
    ike_response.parse_response();
    //todo(Was tun bei notify message, konzept überlegen und aufschreiben, antwort ist kürzer und würde alles verschieben -> neues Paket zum parsen bauen)
    Ok(())
}
