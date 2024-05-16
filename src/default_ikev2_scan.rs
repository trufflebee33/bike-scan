use std::fs;

use rand::random;
use rand::Rng;
use zerocopy::network_endian::U16;
use zerocopy::network_endian::U32;
use zerocopy::network_endian::U64;
use zerocopy::AsBytes;

use crate::ikev2::AttributeType;
use crate::ikev2::AttributeV2;
use crate::ikev2::ExchangeTypeV2;
use crate::ikev2::IkeV2;
use crate::ikev2::IkeV2Header;
use crate::ikev2::KeyExchangePayloadV2;
use crate::ikev2::NoncePayloadV2;
use crate::ikev2::PayloadTypeV2;
use crate::ikev2::Proposal;
use crate::ikev2::ProtocolId;
use crate::ikev2::SecurityAssociationV2;
use crate::ikev2::TransformAttributeV2;
use crate::ikev2::TransformTypeValues;
use crate::ikev2::TransformV2;

#[derive(Debug, Clone)]
pub struct DefaultIkeV2 {
    pub header: IkeV2Header,
    pub sa_payload: SecurityAssociationV2,
    pub proposal: Proposal,
    pub encryption_transform: Vec<TransformAttributeV2>,
    pub prf_transform: Vec<TransformV2>,
    pub integrity_alg: Vec<TransformV2>,
    pub diffie_hellman_transform: Vec<TransformV2>,
    pub key_exchange_payload: KeyExchangePayloadV2,
    pub key_exchange_data: Vec<u8>,
    pub nonce_payload: NoncePayloadV2,
    pub nonce_data: Vec<u8>,
}

impl DefaultIkeV2 {
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
        for encryption_v2 in (1u16..=9)
            .chain(11..=11)
            .chain(14..=14)
            .chain(18..=18)
            .chain(21..=35)
        {
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
        for prf_value in (1u16..=3).chain(9..=9) {
            transform_vec_prf.push(TransformV2 {
                next_transform: 3,
                reserved: 0,
                length: Default::default(),
                transform_type: u8::from(TransformTypeValues::PseudoRandomFunction),
                reserved2: 0,
                transform_id: U16::from(prf_value),
            })
        }
        for integrity_algorithm in (1u16..=4).chain(6..=11) {
            transform_vec_integrity_algorithm.push(TransformV2 {
                next_transform: 3,
                reserved: 0,
                length: Default::default(),
                transform_type: u8::from(TransformTypeValues::IntegrityAlgorithm),
                reserved2: 0,
                transform_id: U16::from(integrity_algorithm),
            })
        }
        for diffie_group in (1u16..=2)
            .chain(5..=5)
            .chain(14..=14)
            .chain(17..=18)
            .chain(22..=27)
            .chain(31..=34)
        {
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
    pub fn generate_key_exchange_data(&mut self) {
        match self.key_exchange_payload.diffie_hellman_group.get() {
            1 => {
                let key_exchange_data = fs::read("key_exchange_data_768.txt");
                self.key_exchange_data = key_exchange_data.expect("couldnt read file")
            }
            2 => {
                let key_exchange_data = fs::read("key_exchange_data_1024.txt");
                self.key_exchange_data = key_exchange_data.expect("couldnt read file")
            }
            3 => {
                let key_exchange_data = fs::read("key_exchange_data_1536.txt");
                self.key_exchange_data = key_exchange_data.expect("couldnt read file")
            }
            4 => {
                let key_exchange_data = fs::read("key_exchange_data_2048.txt");
                self.key_exchange_data = key_exchange_data.expect("couldnt read file")
            }
            5 => {
                let key_exchange_data = fs::read("key_exchange_data_3072.txt");
                self.key_exchange_data = key_exchange_data.expect("couldnt read file")
            }
            6 => {
                let key_exchange_data = fs::read("key_exchange_data_4096.txt");
                self.key_exchange_data = key_exchange_data.expect("couldnt read file")
            }
            7 => {
                let key_exchange_data = fs::read("key_exchange_data_6144.txt");
                self.key_exchange_data = key_exchange_data.expect("couldnt read file")
            }
            8 => {
                let key_exchange_data = fs::read("key_exchange_data_8192.txt");
                self.key_exchange_data = key_exchange_data.expect("couldnt read file");
            }
            _ => {
                println!("No supported Diffie-Hellman Group")
            }
        }
    }
    pub fn generate_nonce_data(&mut self) {
        let nonce_data: Vec<u8> = (0..174).map(|_| random::<u8>()).collect();
        self.nonce_data = nonce_data;
    }
    pub fn calculate_length_v2(&mut self) {
        let mut length = U16::from(0);
        for encr in &mut self.encryption_transform {
            encr.calculate_length();
            length += encr.length
        }

        for prf in &mut self.prf_transform {
            prf.calculate_length();
            length += prf.length
        }

        for integ_alg in &mut self.integrity_alg {
            integ_alg.calculate_length();
            length += integ_alg.length
        }

        for diffie in &mut self.diffie_hellman_transform {
            diffie.calculate_length();
            length += diffie.length;
        }

        let proposal_length = U16::from(8) + length;
        self.proposal.length = proposal_length;
        let sa_length = U16::from(4) + proposal_length;
        self.sa_payload.sa2_length = sa_length;
        self.key_exchange_payload.length = U16::from(8 + (self.key_exchange_data.len() as u16));
        self.nonce_payload.length = U16::from(4 + (self.nonce_data.len() as u16));
        self.header.length = U32::from(28)
            + U32::from(sa_length)
            + U32::from(self.key_exchange_payload.length)
            + U32::from(self.nonce_payload.length);
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
        self.proposal.number_of_transforms = length_checked;
        self.encryption_transform = Vec::from(encryption);
        self.prf_transform = Vec::from(prf);
        self.integrity_alg = Vec::from(integrity_algorithm);
        let mut change_transform = Vec::from(diffie_group);
        change_transform[diffie_group.len() - 1].next_transform =
            u8::from(PayloadTypeV2::NoNextPayload);
        self.diffie_hellman_transform = change_transform
    }

    pub fn convert_to_bytes_v2(&mut self) -> Vec<u8> {
        let mut bytes_v2 = vec![];
        bytes_v2.extend_from_slice(self.header.as_bytes());
        bytes_v2.extend_from_slice(self.sa_payload.as_bytes());
        bytes_v2.extend_from_slice(self.proposal.as_bytes());
        bytes_v2.extend_from_slice(self.encryption_transform.as_bytes());
        bytes_v2.extend_from_slice(self.prf_transform.as_bytes());
        bytes_v2.extend_from_slice(self.integrity_alg.as_bytes());
        bytes_v2.extend_from_slice(self.diffie_hellman_transform.as_bytes());
        bytes_v2.extend_from_slice(self.key_exchange_payload.as_bytes());
        bytes_v2.extend_from_slice(self.key_exchange_data.as_bytes());
        bytes_v2.extend_from_slice(self.nonce_payload.as_bytes());
        bytes_v2.extend_from_slice(self.nonce_data.as_bytes());
        bytes_v2
    }
}
