use std::io;
use std::net::SocketAddr;
use std::thread::sleep;
use std::time;

use rand::distributions::Alphanumeric;
use rand::random;
use rand::Rng;
use tokio::net::UdpSocket;
use zerocopy::network_endian::U128;
use zerocopy::network_endian::U32;
use zerocopy::network_endian::U64;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

use crate::ike::IkeV1;
use crate::ike::IkeV1Header;
use crate::ike::PayloadTypeV1::NoNextPayload;
use crate::ike::PayloadTypeV1::SecurityAssociation;
use crate::ike::ProposalPayload;
use crate::ike::SecurityAssociationV1;
use crate::ikev2::ExchangeTypeV2;
use crate::ikev2::IkeV2;
use crate::ikev2::IkeV2Header;
use crate::ikev2::KeyExchangePayloadV2;
use crate::ikev2::NoncePayloadV2;
use crate::ikev2::PayloadTypeV2;
use crate::ikev2::Proposal;
use crate::ikev2::ProtocolId;
use crate::ikev2::SecurityAssociationV2;
use crate::ikev2::TransformTypeValues::DiffieHellmanGroup;
use crate::parse_ike::ResponsePacket;

pub mod ike;
pub mod ikev2;
pub mod parse_ike;

pub async fn scan() -> io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0".parse::<SocketAddr>().unwrap()).await?;
    let remote_addr = "192.168.122.68:500".parse::<SocketAddr>().unwrap();
    socket.connect(remote_addr).await?;
    /**
    //sending IKE Version 1 packet
    let transforms = IkeV1::build_transforms();
    for chunk in transforms.chunks(255) {
        //calculate random Initiator Security Parameter Index
        let initiator_spi: u64 = rand::thread_rng().gen();
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
        ike_v1.set_transforms(chunk);
        ike_v1.calculate_length();
        let bytes = ike_v1.convert_to_bytes();

        socket.send(&bytes).await.expect("Couldn't send packet");

        //println!("Sende Wrapper Paket an {:?}: {:?} bytes", remote_addr, send_ike_v1);

        let mut buf = [0u8; 112];
        socket
            .recv_from(&mut buf)
            .await
            .expect("couldn't read buffer");

        let byte_slice = buf.as_slice();

        //parse Ike Response
        let ike_response = ResponsePacket::read_from_prefix(byte_slice).expect("Slice too short");
        ike_response.parse_response();
        let seconds = time::Duration::from_millis(1360);
        tokio::time::sleep(seconds).await;
    }*/
    //sending IKE Version 2 Packet
    let transforms_v2 = IkeV2::build_transforms_v2();
    let key_data: u128 = rand::thread_rng().gen();
    for encryption_chunk in transforms_v2.0.chunks(63) {
        for prf_chunk in transforms_v2.1.chunks(63) {
            for integrity_algorithm_chunk in transforms_v2.2.chunks(63) {
                for diffie_group_chunk in transforms_v2.3.chunks(63) {
                    let initiator_spi_v2: u64 = rand::thread_rng().gen();
                    let nonce: u64 = rand::thread_rng().gen();
                    let mut ike_v2 = IkeV2 {
                        header: IkeV2Header {
                            initiator_spi: U64::from(initiator_spi_v2),
                            responder_spi: 0,
                            next_payload: u8::from(PayloadTypeV2::SecurityAssociation),
                            version: 32,
                            exchange_type: u8::from(ExchangeTypeV2::IkeSaInit),
                            flag: 8,
                            message_id: 0,
                            length: Default::default(),
                        },
                        sa_payload_v2: SecurityAssociationV2 {
                            sa2_next_payload: u8::from(PayloadTypeV2::KeyExchange),
                            critical_bit: 0,
                            sa2_length: Default::default(),
                        },
                        proposal_v2: Proposal {
                            next_proposal: 0,
                            reserved: 0,
                            length: Default::default(),
                            proposal_number: 1,
                            protocol_id: ProtocolId::IKE,
                            spi_size: 0,
                            number_of_transforms: Default::default(),
                        },
                        encryption_transforms: vec![],
                        prf_transform: vec![],
                        integrity_algorithm_transform: vec![],
                        diffie_transform: vec![],
                        key_exchange: KeyExchangePayloadV2 {
                            next_payload: u8::from(PayloadTypeV2::Nonce),
                            critical_bit: 0,
                            reserved: 0,
                            length: Default::default(),
                            diffie_hellman_group: U32::from(14),
                            reserved2: Default::default(),
                        },
                        key_exchange_date: U128::from(key_data),
                        nonce_payload: NoncePayloadV2 {
                            next_payload_: 0,
                            critical_bit: 0,
                            reserved: 0,
                            length: Default::default(),
                        },
                        nonce_data: U64::from(nonce),
                    };
                    ike_v2.set_transforms_v2(
                        encryption_chunk,
                        prf_chunk,
                        integrity_algorithm_chunk,
                        diffie_group_chunk,
                    );
                    ike_v2.calculate_length_v2();

                    let bytes_v2 = ike_v2.convert_to_bytes_v2();
                    socket.send(&bytes_v2).await.expect("Couldn't send packet");

                    let mut buf = [0u8; 112];
                    socket
                        .recv_from(&mut buf)
                        .await
                        .expect("couldn't read buffer");
                }
            }
        }
    }
    Ok(())
}
