//! # Bike-Scan
//! das folgende Modul wird zum Parsen von Ike Version 1 verwendet

use zerocopy::network_endian::U16;
use zerocopy::network_endian::U32;
use zerocopy::network_endian::U64;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

use crate::ike::ExchangeType;

///Wrapperstruct für ein IkeV1-Paket
#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponsePacket {
    ///header
    pub header: ResponseHeader,
    ///Security-Association Payload
    pub sa_payload: ResponseSecurityAssociationPayload,
    ///Proposal-Payload
    pub proposal_payload: ResponseProposalPayload,
    ///Transform-Payload
    pub transform_payload: ResponseTransformWrapped,
    ///Hersteller-Id
    pub vendor_id_payload: ResponseVendorID,
    ///Notify Payload für Fehlermeldungen
    pub notify_payload: RespondNotify,
}

impl ResponsePacket {
    ///Die folgende Funktion wird zum Parsen des Pakets verwendet.
    /// Die Attribute aus der Transformation werden als Variablen festgelegt
    /// es werden außerdem leere Vektoren erstellt.
    /// Wenn die Attribute einen Wert > Null haben werden die Vektoren mit dem jeweiligen Wert des Attributs gefüllt.
    /// Anschließend wird mit einer if-Bedingung geprüft, ob die Vektoren nicht leer sind,
    /// wenn dies der Fall ist, werden die Ike Version und der Austauschtyp ausgegeben.
    /// Zum Schluss werden die Inhalte der Vektoren ausgegeben.
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
            //todo(check ike version bevor die attribute in vektor gepusht werden)
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

///Response Wrapper Struct für eine Fehlermeldung
#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponsePacketNotify {
    ///header
    pub header: ResponseHeader,
    ///Fehlermeldung
    pub notify_payload: RespondNotify,
}

///Header der Antwort
#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponseHeader {
    ///Security Parameter Index des Initiators
    pub initiator_spi: U64,
    ///Security Parameter Index des Responder
    /// bekommt den Wert null
    pub responder_spi: u64,
    ///der nächste Payload (häufig Security Association Payload)
    pub next_payload: u8,
    ///die Ike Version
    pub version: u8,
    ///der Modus (eg. Main Mode, aggressive Mode)
    pub exchange_type: u8,
    ///die Flags
    /// sind erst in der zweiten Phase notwendig
    /// und können den Wert null bekommen
    pub flag: u8,
    ///erst in Phase zwei notwendig; muss den Wert null haben
    pub message_id: u32,
    ///Länge des Ike Pakets
    pub length: U32,
}

///Security Association Payload der Antwort
#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponseSecurityAssociationPayload {
    ///nächster Payload (Proposal Payload)
    pub sa_next_payload: u8,
    ///reserviertes Feld, hat Wert null
    pub reserved: u8,
    ///Länge des Payloads
    pub sa_length: U16,
    ///Domain of Interpretation
    /// hat Wert null
    pub sa_doi: U32,
    ///Situation (Varianten in Enum darunter)
    pub sa_situation: U32,
}

///Proposal Payload
#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponseProposalPayload {
    ///nächster Payload (Transformation Payload)
    pub next_payload: u8,
    ///reserviertes Feld, hat den Wert null
    pub reserved: u8,
    ///Länge des Payloads
    pub length: U16,
    ///Nummer des aktuellen Proposals im Payload (fängt bei 1 an)
    pub proposal: u8,
    ///spezifiziert die Protokoll-ID für die aktuelle Übertragung
    /// 1 für IKE
    pub protocol_id: u8,
    ///Größe des Security Parameter Indexes (ist null)
    pub spi_size: u8,
    ///Anzahl der Transformationen
    pub number_of_transforms: u8,
}

///Wrapper Struct für eine Transformation
#[derive(Debug, Copy, Clone, FromZeroes, FromBytes)]
#[repr(packed)]
pub struct ResponseTransformWrapped {
    ///Transform Payload
    pub transform_payload: ResponseTransformPayload,
    ///Verschlüsselungsalgorithmus
    pub encryption_attribute: ResponseAttribute,
    ///Hash Algorithmus
    pub hash_attribute: ResponseAttribute,
    ///Diffie-Hellman Gruppe
    pub diffie_hellman_attribute: ResponseAttribute,
    ///Authentisierungsmethode
    pub authentication_method_attribute: ResponseAttribute,
    ///Zeiteinheit der Lebensdauer
    pub life_type_attribute: ResponseAttribute,
    ///Lebensdauer
    pub life_duration_attribute: ResponseAttribute,
    ///Wert der Lebensdauer
    pub life_duration_value: U32,
}

///Transform Payload
#[derive(Debug, Clone, Copy, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponseTransformPayload {
    ///nächster Payload
    /// drei: Transform folgt
    /// null: letztes Transform
    pub next_payload: u8,
    ///reserviertes Feld
    pub reserved: u8,
    ///Länge der Transformation
    pub length: U16,
    ///Nummer der Transformation
    /// fängt bei eins an
    pub transform_number: u8,
    ///todo
    pub transform_id: u8,
    ///zweites reserviertes Feld
    pub reserved2: U16,
}

///Attribut einer Transformation
#[derive(Debug, Copy, Clone, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponseAttribute {
    ///Attribut Typ (Verschlüsselungsalgorithmus, Hash-Algorithmus, Diffie-Hellman Gruppe, Authentisierungsmethode)
    pub attribute_type: U16,
    ///Attribut Wert oder Länge
    /// in diesem nur der Wert von Bedeutung, weil nur die ersten vier Attribute benötigt werden
    pub attribute_value_or_length: U16,
}

///Hersteller ID
#[derive(Debug, Copy, Clone, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct ResponseVendorID {
    ///nächster Payload
    pub next_payload: u8,
    ///Reservierter Bereich
    pub reserved: u8,
    ///Payload Länge
    pub length: U16,
    ///Hersteller ID
    pub vendor_id: U16,
}

///Notify Payload für Fehlermeldungen
#[derive(Debug, Copy, Clone, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct RespondNotify {
    ///nächster Payload
    pub next_payload: u8,
    ///reservierter Bereich
    pub reserved: u8,
    ///Payload Länge
    pub length: U16,
    ///Domain of Interpretation
    pub doi: U64,
    ///Protokoll ID todo: welche ist ike
    pub protocol_id: u8,
    ///Größe des Security Parameter Indexes
    pub spi_size: u8,
    ///Fehlertyp der Nachricht
    pub notify_message_type: U16,
}
