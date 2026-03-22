use {
    core::mem::MaybeUninit,
    solana_message::Hash,
    solana_message::{
        MessageHeader, VersionedMessage, compiled_instruction::CompiledInstruction,
        v0::MessageAddressTableLookup,
    },
    solana_pubkey::Pubkey,
    solana_signature::Signature,
    solana_transaction::versioned::VersionedTransaction,
    wincode::{
        SchemaRead, SchemaWrite,
        config::Config,
        containers,
        error::{ReadResult, WriteError, WriteResult, invalid_tag_encoding},
        io::{Reader, Writer},
        len::ShortU16,
    },
    wincode_derive::{SchemaRead as DeriveRead, SchemaWrite as DeriveWrite},
};

/// Serializes a [`VersionedTransaction`] into wincode wire format.
///
/// Returns the raw bytes ready to send over the QUIC stream or datagram.
pub fn serialize_transaction(tx: &VersionedTransaction) -> WriteResult<Vec<u8>> {
    let mut bytes = Vec::with_capacity(serialized_transaction_size(tx)?);
    write_transaction(&mut bytes, tx)?;
    Ok(bytes)
}

/// Deserializes a [`VersionedTransaction`] from wincode wire format.
///
/// Accepts bytes previously produced by [`serialize_transaction`].
pub fn deserialize_transaction(bytes: &[u8]) -> ReadResult<VersionedTransaction> {
    let wrapper: WincodeVersionedTransaction = wincode::deserialize(bytes)?;
    Ok(wrapper.into())
}

fn serialized_transaction_size(tx: &VersionedTransaction) -> WriteResult<usize> {
    let mut size = short_u16_size(tx.signatures.len())?;
    size = checked_add(size, checked_mul(tx.signatures.len(), 64)?)?;
    checked_add(size, serialized_message_size(&tx.message)?)
}

fn serialized_message_size(message: &VersionedMessage) -> WriteResult<usize> {
    match message {
        VersionedMessage::Legacy(message) => serialized_message_body_size(
            &message.account_keys,
            &message.recent_blockhash,
            &message.instructions,
        ),
        VersionedMessage::V0(message) => {
            let mut size = checked_add(
                1,
                serialized_message_body_size(
                    &message.account_keys,
                    &message.recent_blockhash,
                    &message.instructions,
                )?,
            )?;
            size = checked_add(size, short_u16_size(message.address_table_lookups.len())?)?;
            for lookup in &message.address_table_lookups {
                size = checked_add(size, serialized_lookup_size(lookup)?)?;
            }
            Ok(size)
        }
    }
}

fn serialized_message_body_size(
    account_keys: &[Pubkey],
    _recent_blockhash: &Hash,
    instructions: &[CompiledInstruction],
) -> WriteResult<usize> {
    let mut size = 3;
    size = checked_add(size, short_u16_size(account_keys.len())?)?;
    size = checked_add(size, checked_mul(account_keys.len(), 32)?)?;
    size = checked_add(size, 32)?;
    size = checked_add(size, short_u16_size(instructions.len())?)?;
    for instruction in instructions {
        size = checked_add(size, serialized_instruction_size(instruction)?)?;
    }
    Ok(size)
}

fn serialized_instruction_size(instruction: &CompiledInstruction) -> WriteResult<usize> {
    let mut size = 1;
    size = checked_add(size, short_u16_size(instruction.accounts.len())?)?;
    size = checked_add(size, instruction.accounts.len())?;
    size = checked_add(size, short_u16_size(instruction.data.len())?)?;
    checked_add(size, instruction.data.len())
}

fn serialized_lookup_size(lookup: &MessageAddressTableLookup) -> WriteResult<usize> {
    let mut size = 32;
    size = checked_add(size, short_u16_size(lookup.writable_indexes.len())?)?;
    size = checked_add(size, lookup.writable_indexes.len())?;
    size = checked_add(size, short_u16_size(lookup.readonly_indexes.len())?)?;
    checked_add(size, lookup.readonly_indexes.len())
}

fn write_transaction(dst: &mut Vec<u8>, tx: &VersionedTransaction) -> WriteResult<()> {
    write_short_u16(dst, tx.signatures.len())?;
    for signature in &tx.signatures {
        dst.extend_from_slice(signature.as_ref());
    }
    write_versioned_message(dst, &tx.message)
}

fn write_versioned_message(dst: &mut Vec<u8>, message: &VersionedMessage) -> WriteResult<()> {
    match message {
        VersionedMessage::Legacy(message) => write_message_body(
            dst,
            &message.header,
            &message.account_keys,
            &message.recent_blockhash,
            &message.instructions,
        ),
        VersionedMessage::V0(message) => {
            dst.push(0x80);
            write_message_body(
                dst,
                &message.header,
                &message.account_keys,
                &message.recent_blockhash,
                &message.instructions,
            )?;
            write_short_u16(dst, message.address_table_lookups.len())?;
            for lookup in &message.address_table_lookups {
                write_lookup(dst, lookup)?;
            }
            Ok(())
        }
    }
}

fn write_message_body(
    dst: &mut Vec<u8>,
    header: &MessageHeader,
    account_keys: &[Pubkey],
    recent_blockhash: &Hash,
    instructions: &[CompiledInstruction],
) -> WriteResult<()> {
    dst.extend_from_slice(&[
        header.num_required_signatures,
        header.num_readonly_signed_accounts,
        header.num_readonly_unsigned_accounts,
    ]);
    write_short_u16(dst, account_keys.len())?;
    for account_key in account_keys {
        dst.extend_from_slice(&account_key.to_bytes());
    }
    dst.extend_from_slice(&recent_blockhash.to_bytes());
    write_short_u16(dst, instructions.len())?;
    for instruction in instructions {
        write_instruction(dst, instruction)?;
    }
    Ok(())
}

fn write_instruction(dst: &mut Vec<u8>, instruction: &CompiledInstruction) -> WriteResult<()> {
    dst.push(instruction.program_id_index);
    write_short_u16(dst, instruction.accounts.len())?;
    dst.extend_from_slice(&instruction.accounts);
    write_short_u16(dst, instruction.data.len())?;
    dst.extend_from_slice(&instruction.data);
    Ok(())
}

fn write_lookup(dst: &mut Vec<u8>, lookup: &MessageAddressTableLookup) -> WriteResult<()> {
    dst.extend_from_slice(&lookup.account_key.to_bytes());
    write_short_u16(dst, lookup.writable_indexes.len())?;
    dst.extend_from_slice(&lookup.writable_indexes);
    write_short_u16(dst, lookup.readonly_indexes.len())?;
    dst.extend_from_slice(&lookup.readonly_indexes);
    Ok(())
}

fn short_u16_size(len: usize) -> WriteResult<usize> {
    if len > u16::MAX as usize {
        return Err(WriteError::LengthEncodingOverflow("u16::MAX"));
    }

    Ok(match len {
        0..=0x7f => 1,
        0x80..=0x3fff => 2,
        _ => 3,
    })
}

fn write_short_u16(dst: &mut Vec<u8>, len: usize) -> WriteResult<()> {
    let len = u16::try_from(len).map_err(|_| WriteError::LengthEncodingOverflow("u16::MAX"))?;
    match len {
        0..=0x7f => dst.push(len as u8),
        0x80..=0x3fff => {
            dst.push(((len & 0x7f) as u8) | 0x80);
            dst.push((len >> 7) as u8);
        }
        _ => {
            dst.push(((len & 0x7f) as u8) | 0x80);
            dst.push((((len >> 7) & 0x7f) as u8) | 0x80);
            dst.push((len >> 14) as u8);
        }
    }
    Ok(())
}

fn checked_add(lhs: usize, rhs: usize) -> WriteResult<usize> {
    lhs.checked_add(rhs)
        .ok_or(WriteError::Custom("serialized transaction size overflow"))
}

fn checked_mul(lhs: usize, rhs: usize) -> WriteResult<usize> {
    lhs.checked_mul(rhs)
        .ok_or(WriteError::Custom("serialized transaction size overflow"))
}

#[derive(DeriveRead, DeriveWrite)]
struct WincodeVersionedTransaction {
    #[wincode(with = "containers::Vec<WincodeSignature, ShortU16>")]
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
#[repr(transparent)]
#[wincode(assert_zero_copy)]
struct WincodeSignature(#[wincode(with = "[u8; 64]")] [u8; 64]);

impl From<&Signature> for WincodeSignature {
    fn from(s: &Signature) -> Self {
        let bytes: &[u8] = s.as_ref();
        WincodeSignature(bytes.try_into().expect("signature is 64 bytes"))
    }
}

enum WincodeVersionedMessage {
    Classic(WincodeClassicMessage),
    V0(WincodeV0Message),
}

unsafe impl<'de, C: Config> SchemaRead<'de, C> for WincodeVersionedMessage {
    type Dst = Self;

    fn read(reader: &mut impl Reader<'de>, dst: &mut MaybeUninit<Self::Dst>) -> ReadResult<()> {
        let first_byte = *reader.peek()?;

        if first_byte < 0x80 {
            let msg = <WincodeClassicMessage as SchemaRead<'de, C>>::get(reader)?;
            dst.write(WincodeVersionedMessage::Classic(msg));
        } else if first_byte == 0x80 {
            reader.consume(1)?;
            let msg = <WincodeV0Message as SchemaRead<'de, C>>::get(reader)?;
            dst.write(WincodeVersionedMessage::V0(msg));
        } else {
            return Err(invalid_tag_encoding(first_byte as usize));
        }
        Ok(())
    }
}

unsafe impl<C: Config> SchemaWrite<C> for WincodeVersionedMessage {
    type Src = Self;

    fn size_of(src: &Self::Src) -> WriteResult<usize> {
        match src {
            WincodeVersionedMessage::Classic(msg) => {
                <WincodeClassicMessage as SchemaWrite<C>>::size_of(msg)
            }
            WincodeVersionedMessage::V0(msg) => {
                let inner = <WincodeV0Message as SchemaWrite<C>>::size_of(msg)?;
                inner
                    .checked_add(1)
                    .ok_or(WriteError::Custom("v0 message size overflow"))
            }
        }
    }

    fn write(writer: &mut impl Writer, src: &Self::Src) -> WriteResult<()> {
        match src {
            WincodeVersionedMessage::Classic(msg) => {
                <WincodeClassicMessage as SchemaWrite<C>>::write(writer, msg)
            }
            WincodeVersionedMessage::V0(msg) => {
                <u8 as SchemaWrite<C>>::write(writer, &0x80)?;
                <WincodeV0Message as SchemaWrite<C>>::write(writer, msg)
            }
        }
    }
}

impl From<WincodeVersionedMessage> for VersionedMessage {
    fn from(msg: WincodeVersionedMessage) -> Self {
        match msg {
            WincodeVersionedMessage::Classic(m) => VersionedMessage::Legacy(m.into()),
            WincodeVersionedMessage::V0(m) => VersionedMessage::V0(m.into()),
        }
    }
}

impl From<&VersionedMessage> for WincodeVersionedMessage {
    fn from(msg: &VersionedMessage) -> Self {
        match msg {
            VersionedMessage::Legacy(m) => {
                WincodeVersionedMessage::Classic(WincodeClassicMessage::from(m))
            }
            VersionedMessage::V0(m) => WincodeVersionedMessage::V0(WincodeV0Message::from(m)),
        }
    }
}

#[derive(DeriveRead, DeriveWrite)]
struct WincodeClassicMessage {
    header: WincodeMessageHeader,
    #[wincode(with = "containers::Vec<WincodePubkey, ShortU16>")]
    account_keys: Vec<WincodePubkey>,
    recent_blockhash: WincodeHash,
    #[wincode(with = "containers::Vec<WincodeCompiledInstruction, ShortU16>")]
    instructions: Vec<WincodeCompiledInstruction>,
}

impl From<WincodeClassicMessage> for solana_message::Message {
    fn from(msg: WincodeClassicMessage) -> Self {
        solana_message::Message {
            header: msg.header.into(),
            account_keys: msg.account_keys.into_iter().map(|p| p.into()).collect(),
            recent_blockhash: msg.recent_blockhash.into(),
            instructions: msg.instructions.into_iter().map(|i| i.into()).collect(),
        }
    }
}

impl From<&solana_message::Message> for WincodeClassicMessage {
    fn from(msg: &solana_message::Message) -> Self {
        WincodeClassicMessage {
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
    #[wincode(with = "containers::Vec<WincodePubkey, ShortU16>")]
    account_keys: Vec<WincodePubkey>,
    recent_blockhash: WincodeHash,
    #[wincode(with = "containers::Vec<WincodeCompiledInstruction, ShortU16>")]
    instructions: Vec<WincodeCompiledInstruction>,
    #[wincode(with = "containers::Vec<WincodeAddressTableLookup, ShortU16>")]
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
#[repr(C)]
#[wincode(assert_zero_copy)]
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
#[repr(transparent)]
#[wincode(assert_zero_copy)]
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
#[repr(transparent)]
#[wincode(assert_zero_copy)]
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
    #[wincode(with = "containers::Vec<u8, ShortU16>")]
    accounts: Vec<u8>,
    #[wincode(with = "containers::Vec<u8, ShortU16>")]
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
    #[wincode(with = "containers::Vec<u8, ShortU16>")]
    writable_indexes: Vec<u8>,
    #[wincode(with = "containers::Vec<u8, ShortU16>")]
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

#[cfg(test)]
mod tests {
    use super::*;

    fn classic_transaction() -> VersionedTransaction {
        VersionedTransaction {
            signatures: vec![Signature::from([0x01; 64])],
            message: VersionedMessage::Legacy(solana_message::Message {
                header: MessageHeader {
                    num_required_signatures: 1,
                    num_readonly_signed_accounts: 0,
                    num_readonly_unsigned_accounts: 0,
                },
                account_keys: vec![Pubkey::from([0x03; 32])],
                recent_blockhash: Hash::from([0x02; 32]),
                instructions: vec![],
            }),
        }
    }

    fn v0_transaction() -> VersionedTransaction {
        VersionedTransaction {
            signatures: vec![Signature::from([0x04; 64])],
            message: VersionedMessage::V0(solana_message::v0::Message {
                header: MessageHeader {
                    num_required_signatures: 1,
                    num_readonly_signed_accounts: 0,
                    num_readonly_unsigned_accounts: 1,
                },
                account_keys: vec![Pubkey::from([0x05; 32]), Pubkey::from([0x06; 32])],
                recent_blockhash: Hash::from([0x07; 32]),
                instructions: vec![CompiledInstruction {
                    program_id_index: 0,
                    accounts: vec![1],
                    data: vec![0xAB, 0xCD],
                }],
                address_table_lookups: vec![MessageAddressTableLookup {
                    account_key: Pubkey::from([0x08; 32]),
                    writable_indexes: vec![0],
                    readonly_indexes: vec![1, 2],
                }],
            }),
        }
    }

    fn assert_transactions_equal(a: &VersionedTransaction, b: &VersionedTransaction) {
        assert_eq!(a.signatures, b.signatures, "signatures mismatch");

        let a_keys = a.message.static_account_keys();
        let b_keys = b.message.static_account_keys();
        assert_eq!(a_keys, b_keys, "account_keys mismatch");

        let a_hash = a.message.recent_blockhash();
        let b_hash = b.message.recent_blockhash();
        assert_eq!(a_hash, b_hash, "recent_blockhash mismatch");

        assert_eq!(
            a.message.instructions(),
            b.message.instructions(),
            "instructions mismatch"
        );

        assert_eq!(
            a.message.address_table_lookups(),
            b.message.address_table_lookups(),
            "address_table_lookups mismatch"
        );
    }

    #[test]
    fn classic_transaction_wincode_roundtrip() {
        let tx = classic_transaction();
        let bytes = serialize_transaction(&tx).expect("serialize");
        let deserialized = deserialize_transaction(&bytes).expect("deserialize");
        assert_transactions_equal(&tx, &deserialized);
    }

    #[test]
    fn v0_transaction_wincode_roundtrip() {
        let tx = v0_transaction();
        let bytes = serialize_transaction(&tx).expect("serialize");
        let deserialized = deserialize_transaction(&bytes).expect("deserialize");
        assert_transactions_equal(&tx, &deserialized);
    }
}
