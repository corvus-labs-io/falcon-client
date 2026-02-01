use {
    core::mem::MaybeUninit,
    solana_message::{
        MessageHeader, VersionedMessage,
        compiled_instruction::CompiledInstruction,
        v0::MessageAddressTableLookup,
    },
    solana_message::Hash,
    solana_pubkey::Pubkey,
    solana_signature::Signature,
    solana_transaction::versioned::VersionedTransaction,
    wincode::{
        SchemaRead, SchemaWrite, containers,
        error::{ReadResult, WriteResult, invalid_tag_encoding},
        io::{Reader, Writer},
        len::ShortU16Len,
    },
    wincode_derive::{SchemaRead as DeriveRead, SchemaWrite as DeriveWrite},
};

pub fn serialize_transaction(tx: &VersionedTransaction) -> WriteResult<Vec<u8>> {
    let wrapper = WincodeVersionedTransaction::from(tx);
    wincode::serialize(&wrapper)
}

pub fn deserialize_transaction(bytes: &[u8]) -> ReadResult<VersionedTransaction> {
    let wrapper: WincodeVersionedTransaction = wincode::deserialize(bytes)?;
    Ok(wrapper.into())
}

#[derive(DeriveRead, DeriveWrite)]
struct WincodeVersionedTransaction {
    #[wincode(with = "containers::Vec<WincodeSignature, ShortU16Len>")]
    signatures: Vec<WincodeSignature>,
    message: WincodeVersionedMessage,
}

impl From<WincodeVersionedTransaction> for VersionedTransaction {
    fn from(tx: WincodeVersionedTransaction) -> Self {
        VersionedTransaction {
            signatures: tx.signatures.into_iter().map(|s| s.0.into()).collect(),
            message: tx.message.into(),
        }
    }
}

impl From<&VersionedTransaction> for WincodeVersionedTransaction {
    fn from(tx: &VersionedTransaction) -> Self {
        WincodeVersionedTransaction {
            signatures: tx.signatures.iter().map(WincodeSignature::from).collect(),
            message: WincodeVersionedMessage::from(&tx.message),
        }
    }
}

#[derive(DeriveRead, DeriveWrite)]
struct WincodeSignature(#[wincode(with = "[u8; 64]")] [u8; 64]);

impl From<&Signature> for WincodeSignature {
    fn from(s: &Signature) -> Self {
        let bytes: &[u8] = s.as_ref();
        WincodeSignature(bytes.try_into().expect("signature is 64 bytes"))
    }
}

enum WincodeVersionedMessage {
    Legacy(WincodeLegacyMessage),
    V0(WincodeV0Message),
}

impl<'de> SchemaRead<'de> for WincodeVersionedMessage {
    type Dst = Self;

    fn read(reader: &mut impl Reader<'de>, dst: &mut MaybeUninit<Self::Dst>) -> ReadResult<()> {
        let first_byte = *reader.peek()?;

        if first_byte < 0x80 {
            let msg = WincodeLegacyMessage::get(reader)?;
            dst.write(WincodeVersionedMessage::Legacy(msg));
        } else if first_byte == 0x80 {
            reader.consume(1)?;
            let msg = WincodeV0Message::get(reader)?;
            dst.write(WincodeVersionedMessage::V0(msg));
        } else {
            return Err(invalid_tag_encoding(first_byte as usize));
        }
        Ok(())
    }
}

impl SchemaWrite for WincodeVersionedMessage {
    type Src = Self;

    fn size_of(src: &Self::Src) -> WriteResult<usize> {
        match src {
            WincodeVersionedMessage::Legacy(msg) => WincodeLegacyMessage::size_of(msg),
            WincodeVersionedMessage::V0(msg) => Ok(1 + WincodeV0Message::size_of(msg)?),
        }
    }

    fn write(writer: &mut impl Writer, src: &Self::Src) -> WriteResult<()> {
        match src {
            WincodeVersionedMessage::Legacy(msg) => WincodeLegacyMessage::write(writer, msg),
            WincodeVersionedMessage::V0(msg) => {
                u8::write(writer, &0x80)?;
                WincodeV0Message::write(writer, msg)
            }
        }
    }
}

impl From<WincodeVersionedMessage> for VersionedMessage {
    fn from(msg: WincodeVersionedMessage) -> Self {
        match msg {
            WincodeVersionedMessage::Legacy(m) => VersionedMessage::Legacy(m.into()),
            WincodeVersionedMessage::V0(m) => VersionedMessage::V0(m.into()),
        }
    }
}

impl From<&VersionedMessage> for WincodeVersionedMessage {
    fn from(msg: &VersionedMessage) -> Self {
        match msg {
            VersionedMessage::Legacy(m) => {
                WincodeVersionedMessage::Legacy(WincodeLegacyMessage::from(m))
            }
            VersionedMessage::V0(m) => WincodeVersionedMessage::V0(WincodeV0Message::from(m)),
        }
    }
}

#[derive(DeriveRead, DeriveWrite)]
struct WincodeLegacyMessage {
    header: WincodeMessageHeader,
    #[wincode(with = "containers::Vec<WincodePubkey, ShortU16Len>")]
    account_keys: Vec<WincodePubkey>,
    recent_blockhash: WincodeHash,
    #[wincode(with = "containers::Vec<WincodeCompiledInstruction, ShortU16Len>")]
    instructions: Vec<WincodeCompiledInstruction>,
}

impl From<WincodeLegacyMessage> for solana_message::Message {
    fn from(msg: WincodeLegacyMessage) -> Self {
        solana_message::Message {
            header: msg.header.into(),
            account_keys: msg.account_keys.into_iter().map(|p| p.into()).collect(),
            recent_blockhash: msg.recent_blockhash.into(),
            instructions: msg.instructions.into_iter().map(|i| i.into()).collect(),
        }
    }
}

impl From<&solana_message::Message> for WincodeLegacyMessage {
    fn from(msg: &solana_message::Message) -> Self {
        WincodeLegacyMessage {
            header: WincodeMessageHeader::from(&msg.header),
            account_keys: msg.account_keys.iter().map(WincodePubkey::from).collect(),
            recent_blockhash: WincodeHash::from(&msg.recent_blockhash),
            instructions: msg
                .instructions
                .iter()
                .map(WincodeCompiledInstruction::from)
                .collect(),
        }
    }
}

#[derive(DeriveRead, DeriveWrite)]
struct WincodeV0Message {
    header: WincodeMessageHeader,
    #[wincode(with = "containers::Vec<WincodePubkey, ShortU16Len>")]
    account_keys: Vec<WincodePubkey>,
    recent_blockhash: WincodeHash,
    #[wincode(with = "containers::Vec<WincodeCompiledInstruction, ShortU16Len>")]
    instructions: Vec<WincodeCompiledInstruction>,
    #[wincode(with = "containers::Vec<WincodeAddressTableLookup, ShortU16Len>")]
    address_table_lookups: Vec<WincodeAddressTableLookup>,
}

impl From<WincodeV0Message> for solana_message::v0::Message {
    fn from(msg: WincodeV0Message) -> Self {
        solana_message::v0::Message {
            header: msg.header.into(),
            account_keys: msg.account_keys.into_iter().map(|p| p.into()).collect(),
            recent_blockhash: msg.recent_blockhash.into(),
            instructions: msg.instructions.into_iter().map(|i| i.into()).collect(),
            address_table_lookups: msg
                .address_table_lookups
                .into_iter()
                .map(|l| l.into())
                .collect(),
        }
    }
}

impl From<&solana_message::v0::Message> for WincodeV0Message {
    fn from(msg: &solana_message::v0::Message) -> Self {
        WincodeV0Message {
            header: WincodeMessageHeader::from(&msg.header),
            account_keys: msg.account_keys.iter().map(WincodePubkey::from).collect(),
            recent_blockhash: WincodeHash::from(&msg.recent_blockhash),
            instructions: msg
                .instructions
                .iter()
                .map(WincodeCompiledInstruction::from)
                .collect(),
            address_table_lookups: msg
                .address_table_lookups
                .iter()
                .map(WincodeAddressTableLookup::from)
                .collect(),
        }
    }
}

#[derive(DeriveRead, DeriveWrite)]
struct WincodeMessageHeader {
    num_required_signatures: u8,
    num_readonly_signed_accounts: u8,
    num_readonly_unsigned_accounts: u8,
}

impl From<WincodeMessageHeader> for MessageHeader {
    fn from(h: WincodeMessageHeader) -> Self {
        MessageHeader {
            num_required_signatures: h.num_required_signatures,
            num_readonly_signed_accounts: h.num_readonly_signed_accounts,
            num_readonly_unsigned_accounts: h.num_readonly_unsigned_accounts,
        }
    }
}

impl From<&MessageHeader> for WincodeMessageHeader {
    fn from(h: &MessageHeader) -> Self {
        WincodeMessageHeader {
            num_required_signatures: h.num_required_signatures,
            num_readonly_signed_accounts: h.num_readonly_signed_accounts,
            num_readonly_unsigned_accounts: h.num_readonly_unsigned_accounts,
        }
    }
}

#[derive(DeriveRead, DeriveWrite)]
struct WincodePubkey(#[wincode(with = "[u8; 32]")] [u8; 32]);

impl From<WincodePubkey> for Pubkey {
    fn from(p: WincodePubkey) -> Self {
        Pubkey::from(p.0)
    }
}

impl From<&Pubkey> for WincodePubkey {
    fn from(p: &Pubkey) -> Self {
        WincodePubkey(p.to_bytes())
    }
}

#[derive(DeriveRead, DeriveWrite)]
struct WincodeHash(#[wincode(with = "[u8; 32]")] [u8; 32]);

impl From<WincodeHash> for Hash {
    fn from(h: WincodeHash) -> Self {
        Hash::from(h.0)
    }
}

impl From<&Hash> for WincodeHash {
    fn from(h: &Hash) -> Self {
        WincodeHash(h.to_bytes())
    }
}

#[derive(DeriveRead, DeriveWrite)]
struct WincodeCompiledInstruction {
    program_id_index: u8,
    #[wincode(with = "containers::Vec<u8, ShortU16Len>")]
    accounts: Vec<u8>,
    #[wincode(with = "containers::Vec<u8, ShortU16Len>")]
    data: Vec<u8>,
}

impl From<WincodeCompiledInstruction> for CompiledInstruction {
    fn from(i: WincodeCompiledInstruction) -> Self {
        CompiledInstruction {
            program_id_index: i.program_id_index,
            accounts: i.accounts,
            data: i.data,
        }
    }
}

impl From<&CompiledInstruction> for WincodeCompiledInstruction {
    fn from(i: &CompiledInstruction) -> Self {
        WincodeCompiledInstruction {
            program_id_index: i.program_id_index,
            accounts: i.accounts.clone(),
            data: i.data.clone(),
        }
    }
}

#[derive(DeriveRead, DeriveWrite)]
struct WincodeAddressTableLookup {
    account_key: WincodePubkey,
    #[wincode(with = "containers::Vec<u8, ShortU16Len>")]
    writable_indexes: Vec<u8>,
    #[wincode(with = "containers::Vec<u8, ShortU16Len>")]
    readonly_indexes: Vec<u8>,
}

impl From<WincodeAddressTableLookup> for MessageAddressTableLookup {
    fn from(l: WincodeAddressTableLookup) -> Self {
        MessageAddressTableLookup {
            account_key: l.account_key.into(),
            writable_indexes: l.writable_indexes,
            readonly_indexes: l.readonly_indexes,
        }
    }
}

impl From<&MessageAddressTableLookup> for WincodeAddressTableLookup {
    fn from(l: &MessageAddressTableLookup) -> Self {
        WincodeAddressTableLookup {
            account_key: WincodePubkey::from(&l.account_key),
            writable_indexes: l.writable_indexes.clone(),
            readonly_indexes: l.readonly_indexes.clone(),
        }
    }
}
