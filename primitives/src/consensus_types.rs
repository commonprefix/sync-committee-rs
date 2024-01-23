use crate::{
	constants::{
		BlsPublicKey, BlsSignature, Bytes32, Epoch, ExecutionAddress, Gwei, Hash32,
		ParticipationFlags, Root, Slot, ValidatorIndex, Version, WithdrawalIndex,
		DEPOSIT_PROOF_LENGTH, JUSTIFICATION_BITS_LENGTH,
	},
	ssz::{ByteList, ByteVector},
};
use alloc::{vec, vec::Vec};
use ssz_rs::{prelude::*, List, Vector};
use superstruct::superstruct;

#[derive(
	Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize,
)]
pub struct BeaconBlockHeader {
	#[serde(with = "crate::serde::as_string")]
	pub slot: u64,
	#[serde(with = "crate::serde::as_string")]
	pub proposer_index: u64,
	pub parent_root: Root,
	pub state_root: Root,
	pub body_root: Root,
}

#[derive(
	Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize,
)]
pub struct Checkpoint {
	#[serde(with = "crate::serde::as_string")]
	pub epoch: u64,
	pub root: Root,
}

#[derive(
	Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize,
)]
pub struct Eth1Data {
	pub deposit_root: Root,
	#[serde(with = "crate::serde::as_string")]
	pub deposit_count: u64,
	pub block_hash: Hash32,
}

#[derive(
	Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize,
)]
pub struct Validator {
	#[cfg_attr(feature = "serialize", serde(rename = "pubkey"))]
	pub public_key: BlsPublicKey,
	pub withdrawal_credentials: Bytes32,
	#[serde(with = "crate::serde::as_string")]
	pub effective_balance: Gwei,
	pub slashed: bool,
	// Status epochs
	#[serde(with = "crate::serde::as_string")]
	pub activation_eligibility_epoch: Epoch,
	#[serde(with = "crate::serde::as_string")]
	pub activation_epoch: Epoch,
	#[serde(with = "crate::serde::as_string")]
	pub exit_epoch: Epoch,
	#[serde(with = "crate::serde::as_string")]
	pub withdrawable_epoch: Epoch,
}

#[derive(
	Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize,
)]
pub struct ProposerSlashing {
	pub signed_header_1: SignedBeaconBlockHeader,
	pub signed_header_2: SignedBeaconBlockHeader,
}

#[derive(
	Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize,
)]
pub struct SignedBeaconBlockHeader {
	pub message: BeaconBlockHeader,
	pub signature: BlsSignature,
}

#[derive(
	Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize,
)]
pub struct IndexedAttestation<const MAX_VALIDATORS_PER_COMMITTEE: usize> {
	#[cfg_attr(feature = "serialize", serde(with = "crate::serde::collection_over_string"))]
	pub attesting_indices: List<u64, MAX_VALIDATORS_PER_COMMITTEE>,
	pub data: AttestationData,
	pub signature: BlsSignature,
}

#[derive(
	Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize,
)]
pub struct AttestationData {
	#[serde(with = "crate::serde::as_string")]
	pub slot: u64,
	#[serde(with = "crate::serde::as_string")]
	pub index: u64,
	pub beacon_block_root: Root,
	pub source: Checkpoint,
	pub target: Checkpoint,
}

#[derive(
	Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize,
)]
pub struct AttesterSlashing<const MAX_VALIDATORS_PER_COMMITTEE: usize> {
	pub attestation_1: IndexedAttestation<MAX_VALIDATORS_PER_COMMITTEE>,
	pub attestation_2: IndexedAttestation<MAX_VALIDATORS_PER_COMMITTEE>,
}

#[derive(
	Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize,
)]
pub struct Attestation<const MAX_VALIDATORS_PER_COMMITTEE: usize> {
	pub aggregation_bits: Bitlist<MAX_VALIDATORS_PER_COMMITTEE>,
	pub data: AttestationData,
	pub signature: BlsSignature,
}

#[derive(
	Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize,
)]
pub struct Deposit {
	pub proof: Vector<Hash32, DEPOSIT_PROOF_LENGTH>,
	pub data: DepositData,
}

#[derive(
	Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize,
)]
pub struct DepositData {
	#[cfg_attr(feature = "serialize", serde(rename = "pubkey"))]
	pub public_key: BlsPublicKey,
	pub withdrawal_credentials: Hash32,
	#[serde(with = "crate::serde::as_string")]
	pub amount: u64,
	pub signature: BlsSignature,
}

#[derive(
	Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize,
)]
pub struct VoluntaryExit {
	#[serde(with = "crate::serde::as_string")]
	pub epoch: u64,
	#[serde(with = "crate::serde::as_string")]
	pub validator_index: u64,
}

#[derive(
	Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize,
)]
pub struct SignedVoluntaryExit {
	pub message: VoluntaryExit,
	pub signature: BlsSignature,
}

#[derive(
	Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize,
)]
pub struct SyncAggregate<const SYNC_COMMITTEE_SIZE: usize> {
	pub sync_committee_bits: Bitvector<SYNC_COMMITTEE_SIZE>,
	pub sync_committee_signature: BlsSignature,
}

#[derive(
	Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize,
)]
pub struct SyncCommittee<const SYNC_COMMITTEE_SIZE: usize> {
	#[cfg_attr(feature = "serialize", serde(rename = "pubkeys"))]
	pub public_keys: Vector<BlsPublicKey, SYNC_COMMITTEE_SIZE>,
	#[cfg_attr(feature = "serialize", serde(rename = "aggregate_pubkey"))]
	pub aggregate_public_key: BlsPublicKey,
}

#[derive(
	Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize,
)]
pub struct Withdrawal {
	#[serde(with = "crate::serde::as_string")]
	pub index: WithdrawalIndex,
	#[serde(with = "crate::serde::as_string")]
	pub validator_index: ValidatorIndex,
	pub address: ExecutionAddress,
	#[serde(with = "crate::serde::as_string")]
	pub amount: Gwei,
}

#[derive(
	Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize,
)]
pub struct BlsToExecutionChange {
	#[serde(with = "crate::serde::as_string")]
	pub validator_index: ValidatorIndex,
	#[cfg_attr(feature = "serde", serde(rename = "from_bls_pubkey"))]
	pub from_bls_public_key: BlsPublicKey,
	pub to_execution_address: ExecutionAddress,
}

#[derive(
	Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize,
)]
pub struct SignedBlsToExecutionChange {
	message: BlsToExecutionChange,
	signature: BlsSignature,
}

pub type Transaction<const MAX_BYTES_PER_TRANSACTION: usize> = ByteList<MAX_BYTES_PER_TRANSACTION>;

#[superstruct(
	variants(Bellatrix, Capella, Deneb),
	variant_attributes(
		derive(
			Debug,
			Clone,
			SimpleSerialize,
			PartialEq,
			Eq,
			Default,
			serde::Deserialize,
			serde::Serialize
		),
		serde(deny_unknown_fields)
	)
)]
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(untagged)]
pub struct ExecutionPayload<
	const BYTES_PER_LOGS_BLOOM: usize,
	const MAX_EXTRA_DATA_BYTES: usize,
	const MAX_BYTES_PER_TRANSACTION: usize,
	const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
	const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
> {
	pub parent_hash: Hash32,
	pub fee_recipient: ExecutionAddress,
	pub state_root: Bytes32,
	pub receipts_root: Bytes32,
	pub logs_bloom: ByteVector<BYTES_PER_LOGS_BLOOM>,
	pub prev_randao: Bytes32,
	#[serde(with = "crate::serde::as_string")]
	pub block_number: u64,
	#[serde(with = "crate::serde::as_string")]
	pub gas_limit: u64,
	#[serde(with = "crate::serde::as_string")]
	pub gas_used: u64,
	#[serde(with = "crate::serde::as_string")]
	pub timestamp: u64,
	pub extra_data: ByteList<MAX_EXTRA_DATA_BYTES>,
	pub base_fee_per_gas: U256,
	pub block_hash: Hash32,
	pub transactions: List<Transaction<MAX_BYTES_PER_TRANSACTION>, MAX_TRANSACTIONS_PER_PAYLOAD>,
	#[superstruct(only(Capella, Deneb))]
	pub withdrawals: List<Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD>,
	#[superstruct(only(Deneb))]
	#[serde(with = "crate::serde::as_string")]
	pub blob_gas_used: u64,
	#[superstruct(only(Deneb))]
	#[serde(with = "crate::serde::as_string")]
	pub excess_blob_gas: u64,
}

impl<
		const BYTES_PER_LOGS_BLOOM: usize,
		const MAX_EXTRA_DATA_BYTES: usize,
		const MAX_BYTES_PER_TRANSACTION: usize,
		const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
		const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
	> Default
	for ExecutionPayload<
		BYTES_PER_LOGS_BLOOM,
		MAX_EXTRA_DATA_BYTES,
		MAX_BYTES_PER_TRANSACTION,
		MAX_TRANSACTIONS_PER_PAYLOAD,
		MAX_WITHDRAWALS_PER_PAYLOAD,
	>
{
	fn default() -> Self {
		ExecutionPayload::Capella(ExecutionPayloadCapella::default())
	}
}

impl<
		const BYTES_PER_LOGS_BLOOM: usize,
		const MAX_EXTRA_DATA_BYTES: usize,
		const MAX_BYTES_PER_TRANSACTION: usize,
		const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
		const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
	> ssz_rs::Merkleized
	for ExecutionPayload<
		BYTES_PER_LOGS_BLOOM,
		MAX_EXTRA_DATA_BYTES,
		MAX_BYTES_PER_TRANSACTION,
		MAX_TRANSACTIONS_PER_PAYLOAD,
		MAX_WITHDRAWALS_PER_PAYLOAD,
	>
{
	fn hash_tree_root(&mut self) -> Result<Node, MerkleizationError> {
		let t = self.clone();
		if let ExecutionPayload::Bellatrix(mut inner) = t {
			inner.hash_tree_root()
		} else if let ExecutionPayload::Capella(mut inner) = t {
			inner.hash_tree_root()
		} else if let ExecutionPayload::Deneb(mut inner) = t {
			inner.hash_tree_root()
		} else {
			unreachable!()
		}
	}
}

impl<
		const BYTES_PER_LOGS_BLOOM: usize,
		const MAX_EXTRA_DATA_BYTES: usize,
		const MAX_BYTES_PER_TRANSACTION: usize,
		const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
		const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
	> ssz_rs::Sized
	for ExecutionPayload<
		BYTES_PER_LOGS_BLOOM,
		MAX_EXTRA_DATA_BYTES,
		MAX_BYTES_PER_TRANSACTION,
		MAX_TRANSACTIONS_PER_PAYLOAD,
		MAX_WITHDRAWALS_PER_PAYLOAD,
	>
{
	fn is_variable_size() -> bool {
		true
	}

	fn ssz_size_hint() -> usize {
		0
	}
}

impl<
		const BYTES_PER_LOGS_BLOOM: usize,
		const MAX_EXTRA_DATA_BYTES: usize,
		const MAX_BYTES_PER_TRANSACTION: usize,
		const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
		const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
	> ssz_rs::Serialize
	for ExecutionPayload<
		BYTES_PER_LOGS_BLOOM,
		MAX_EXTRA_DATA_BYTES,
		MAX_BYTES_PER_TRANSACTION,
		MAX_TRANSACTIONS_PER_PAYLOAD,
		MAX_WITHDRAWALS_PER_PAYLOAD,
	>
{
	fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
		match self {
			ExecutionPayload::Bellatrix(inner) => inner.serialize(buffer),
			ExecutionPayload::Capella(inner) => inner.serialize(buffer),
			ExecutionPayload::Deneb(inner) => inner.serialize(buffer),
		}
	}
}

impl<
		const BYTES_PER_LOGS_BLOOM: usize,
		const MAX_EXTRA_DATA_BYTES: usize,
		const MAX_BYTES_PER_TRANSACTION: usize,
		const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
		const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
	> ssz_rs::Deserialize
	for ExecutionPayload<
		BYTES_PER_LOGS_BLOOM,
		MAX_EXTRA_DATA_BYTES,
		MAX_BYTES_PER_TRANSACTION,
		MAX_TRANSACTIONS_PER_PAYLOAD,
		MAX_WITHDRAWALS_PER_PAYLOAD,
	>
{
	fn deserialize(_encoding: &[u8]) -> Result<Self, DeserializeError>
	where
		Self: Sized,
	{
		panic!("not implemented");
	}
}

impl<
		const BYTES_PER_LOGS_BLOOM: usize,
		const MAX_EXTRA_DATA_BYTES: usize,
		const MAX_BYTES_PER_TRANSACTION: usize,
		const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
		const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
	> ssz_rs::SszReflect
	for ExecutionPayload<
		BYTES_PER_LOGS_BLOOM,
		MAX_EXTRA_DATA_BYTES,
		MAX_BYTES_PER_TRANSACTION,
		MAX_TRANSACTIONS_PER_PAYLOAD,
		MAX_WITHDRAWALS_PER_PAYLOAD,
	>
{
	fn ssz_type_class(&self) -> ssz_rs::SszTypeClass {
		match self {
			ExecutionPayload::Bellatrix(inner) => inner.ssz_type_class(),
			ExecutionPayload::Capella(inner) => inner.ssz_type_class(),
			ExecutionPayload::Deneb(inner) => inner.ssz_type_class(),
		}
	}
}

impl<
		const BYTES_PER_LOGS_BLOOM: usize,
		const MAX_EXTRA_DATA_BYTES: usize,
		const MAX_BYTES_PER_TRANSACTION: usize,
		const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
		const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
	> ssz_rs::SimpleSerialize
	for ExecutionPayload<
		BYTES_PER_LOGS_BLOOM,
		MAX_EXTRA_DATA_BYTES,
		MAX_BYTES_PER_TRANSACTION,
		MAX_TRANSACTIONS_PER_PAYLOAD,
		MAX_WITHDRAWALS_PER_PAYLOAD,
	>
{
}

#[derive(
	Default, Debug, Clone, SimpleSerialize, PartialEq, Eq, serde::Deserialize, serde::Serialize,
)]
pub struct ExecutionPayloadHeader<
	const BYTES_PER_LOGS_BLOOM: usize,
	const MAX_EXTRA_DATA_BYTES: usize,
> {
	pub parent_hash: Hash32,
	pub fee_recipient: ExecutionAddress,
	pub state_root: Bytes32,
	pub receipts_root: Bytes32,
	pub logs_bloom: ByteVector<BYTES_PER_LOGS_BLOOM>,
	pub prev_randao: Bytes32,
	#[serde(with = "crate::serde::as_string")]
	pub block_number: u64,
	#[serde(with = "crate::serde::as_string")]
	pub gas_limit: u64,
	#[serde(with = "crate::serde::as_string")]
	pub gas_used: u64,
	#[serde(with = "crate::serde::as_string")]
	pub timestamp: u64,
	pub extra_data: ByteList<MAX_EXTRA_DATA_BYTES>,
	pub base_fee_per_gas: U256,
	pub block_hash: Hash32,
	pub transactions_root: Root,
	pub withdrawals_root: Root,
	// TODO: Must use superstruct for this field as well
	#[cfg_attr(feature = "serialize", serde(with = "crate::serde::as_string"))]
	pub blob_gas_used: u64,
	// TODO: Must use superstruct for this field as well
	#[cfg_attr(feature = "serialize", serde(with = "crate::serde::as_string"))]
	pub excess_blob_gas: u64,
}

#[superstruct(
	variants(Bellatrix, Capella, Deneb),
	variant_attributes(
		derive(
			Debug,
			Clone,
			SimpleSerialize,
			PartialEq,
			Eq,
			Default,
			serde::Deserialize,
			serde::Serialize
		),
		serde(deny_unknown_fields)
	)
)]
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(untagged)]
pub struct BeaconBlockBody<
	const MAX_PROPOSER_SLASHINGS: usize,
	const MAX_VALIDATORS_PER_COMMITTEE: usize,
	const MAX_ATTESTER_SLASHINGS: usize,
	const MAX_ATTESTATIONS: usize,
	const MAX_DEPOSITS: usize,
	const MAX_VOLUNTARY_EXITS: usize,
	const SYNC_COMMITTEE_SIZE: usize,
	const BYTES_PER_LOGS_BLOOM: usize,
	const MAX_EXTRA_DATA_BYTES: usize,
	const MAX_BYTES_PER_TRANSACTION: usize,
	const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
	const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
	const MAX_BLS_TO_EXECUTION_CHANGES: usize,
> {
	pub randao_reveal: BlsSignature,
	pub eth1_data: Eth1Data,
	pub graffiti: Bytes32,
	pub proposer_slashings: List<ProposerSlashing, MAX_PROPOSER_SLASHINGS>,
	pub attester_slashings:
		List<AttesterSlashing<MAX_VALIDATORS_PER_COMMITTEE>, MAX_ATTESTER_SLASHINGS>,
	pub attestations: List<Attestation<MAX_VALIDATORS_PER_COMMITTEE>, MAX_ATTESTATIONS>,
	pub deposits: List<Deposit, MAX_DEPOSITS>,
	pub voluntary_exits: List<SignedVoluntaryExit, MAX_VOLUNTARY_EXITS>,
	pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
	pub execution_payload: ExecutionPayload<
		BYTES_PER_LOGS_BLOOM,
		MAX_EXTRA_DATA_BYTES,
		MAX_BYTES_PER_TRANSACTION,
		MAX_TRANSACTIONS_PER_PAYLOAD,
		MAX_WITHDRAWALS_PER_PAYLOAD,
	>,
	#[superstruct(only(Capella, Deneb))]
	pub bls_to_execution_changes: List<SignedBlsToExecutionChange, MAX_BLS_TO_EXECUTION_CHANGES>,
	#[superstruct(only(Deneb))]
	pub blob_kzg_commitments: List<ByteVector<48>, 4096>,
}

impl<
		const MAX_PROPOSER_SLASHINGS: usize,
		const MAX_VALIDATORS_PER_COMMITTEE: usize,
		const MAX_ATTESTER_SLASHINGS: usize,
		const MAX_ATTESTATIONS: usize,
		const MAX_DEPOSITS: usize,
		const MAX_VOLUNTARY_EXITS: usize,
		const SYNC_COMMITTEE_SIZE: usize,
		const BYTES_PER_LOGS_BLOOM: usize,
		const MAX_EXTRA_DATA_BYTES: usize,
		const MAX_BYTES_PER_TRANSACTION: usize,
		const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
		const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
		const MAX_BLS_TO_EXECUTION_CHANGES: usize,
	> Default
	for BeaconBlockBody<
		MAX_PROPOSER_SLASHINGS,
		MAX_VALIDATORS_PER_COMMITTEE,
		MAX_ATTESTER_SLASHINGS,
		MAX_ATTESTATIONS,
		MAX_DEPOSITS,
		MAX_VOLUNTARY_EXITS,
		SYNC_COMMITTEE_SIZE,
		BYTES_PER_LOGS_BLOOM,
		MAX_EXTRA_DATA_BYTES,
		MAX_BYTES_PER_TRANSACTION,
		MAX_TRANSACTIONS_PER_PAYLOAD,
		MAX_WITHDRAWALS_PER_PAYLOAD,
		MAX_BLS_TO_EXECUTION_CHANGES,
	>
{
	fn default() -> Self {
		BeaconBlockBody::Capella(BeaconBlockBodyCapella::default())
	}
}

impl<
		const MAX_PROPOSER_SLASHINGS: usize,
		const MAX_VALIDATORS_PER_COMMITTEE: usize,
		const MAX_ATTESTER_SLASHINGS: usize,
		const MAX_ATTESTATIONS: usize,
		const MAX_DEPOSITS: usize,
		const MAX_VOLUNTARY_EXITS: usize,
		const SYNC_COMMITTEE_SIZE: usize,
		const BYTES_PER_LOGS_BLOOM: usize,
		const MAX_EXTRA_DATA_BYTES: usize,
		const MAX_BYTES_PER_TRANSACTION: usize,
		const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
		const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
		const MAX_BLS_TO_EXECUTION_CHANGES: usize,
	> ssz_rs::Merkleized
	for BeaconBlockBody<
		MAX_PROPOSER_SLASHINGS,
		MAX_VALIDATORS_PER_COMMITTEE,
		MAX_ATTESTER_SLASHINGS,
		MAX_ATTESTATIONS,
		MAX_DEPOSITS,
		MAX_VOLUNTARY_EXITS,
		SYNC_COMMITTEE_SIZE,
		BYTES_PER_LOGS_BLOOM,
		MAX_EXTRA_DATA_BYTES,
		MAX_BYTES_PER_TRANSACTION,
		MAX_TRANSACTIONS_PER_PAYLOAD,
		MAX_WITHDRAWALS_PER_PAYLOAD,
		MAX_BLS_TO_EXECUTION_CHANGES,
	>
{
	fn hash_tree_root(&mut self) -> Result<Node, MerkleizationError> {
		let t = self.clone();
		if let BeaconBlockBody::Bellatrix(mut inner) = t {
			inner.hash_tree_root()
		} else if let BeaconBlockBody::Capella(mut inner) = t {
			inner.hash_tree_root()
		} else if let BeaconBlockBody::Deneb(mut inner) = t {
			inner.hash_tree_root()
		} else {
			unreachable!()
		}
	}
}

impl<
		const MAX_PROPOSER_SLASHINGS: usize,
		const MAX_VALIDATORS_PER_COMMITTEE: usize,
		const MAX_ATTESTER_SLASHINGS: usize,
		const MAX_ATTESTATIONS: usize,
		const MAX_DEPOSITS: usize,
		const MAX_VOLUNTARY_EXITS: usize,
		const SYNC_COMMITTEE_SIZE: usize,
		const BYTES_PER_LOGS_BLOOM: usize,
		const MAX_EXTRA_DATA_BYTES: usize,
		const MAX_BYTES_PER_TRANSACTION: usize,
		const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
		const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
		const MAX_BLS_TO_EXECUTION_CHANGES: usize,
	> ssz_rs::Sized
	for BeaconBlockBody<
		MAX_PROPOSER_SLASHINGS,
		MAX_VALIDATORS_PER_COMMITTEE,
		MAX_ATTESTER_SLASHINGS,
		MAX_ATTESTATIONS,
		MAX_DEPOSITS,
		MAX_VOLUNTARY_EXITS,
		SYNC_COMMITTEE_SIZE,
		BYTES_PER_LOGS_BLOOM,
		MAX_EXTRA_DATA_BYTES,
		MAX_BYTES_PER_TRANSACTION,
		MAX_TRANSACTIONS_PER_PAYLOAD,
		MAX_WITHDRAWALS_PER_PAYLOAD,
		MAX_BLS_TO_EXECUTION_CHANGES,
	>
{
	fn is_variable_size() -> bool {
		true
	}

	fn ssz_size_hint() -> usize {
		0
	}
}

impl<
		const MAX_PROPOSER_SLASHINGS: usize,
		const MAX_VALIDATORS_PER_COMMITTEE: usize,
		const MAX_ATTESTER_SLASHINGS: usize,
		const MAX_ATTESTATIONS: usize,
		const MAX_DEPOSITS: usize,
		const MAX_VOLUNTARY_EXITS: usize,
		const SYNC_COMMITTEE_SIZE: usize,
		const BYTES_PER_LOGS_BLOOM: usize,
		const MAX_EXTRA_DATA_BYTES: usize,
		const MAX_BYTES_PER_TRANSACTION: usize,
		const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
		const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
		const MAX_BLS_TO_EXECUTION_CHANGES: usize,
	> ssz_rs::Serialize
	for BeaconBlockBody<
		MAX_PROPOSER_SLASHINGS,
		MAX_VALIDATORS_PER_COMMITTEE,
		MAX_ATTESTER_SLASHINGS,
		MAX_ATTESTATIONS,
		MAX_DEPOSITS,
		MAX_VOLUNTARY_EXITS,
		SYNC_COMMITTEE_SIZE,
		BYTES_PER_LOGS_BLOOM,
		MAX_EXTRA_DATA_BYTES,
		MAX_BYTES_PER_TRANSACTION,
		MAX_TRANSACTIONS_PER_PAYLOAD,
		MAX_WITHDRAWALS_PER_PAYLOAD,
		MAX_BLS_TO_EXECUTION_CHANGES,
	>
{
	fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
		match self {
			BeaconBlockBody::Bellatrix(inner) => inner.serialize(buffer),
			BeaconBlockBody::Capella(inner) => inner.serialize(buffer),
			BeaconBlockBody::Deneb(inner) => inner.serialize(buffer),
		}
	}
}

impl<
		const MAX_PROPOSER_SLASHINGS: usize,
		const MAX_VALIDATORS_PER_COMMITTEE: usize,
		const MAX_ATTESTER_SLASHINGS: usize,
		const MAX_ATTESTATIONS: usize,
		const MAX_DEPOSITS: usize,
		const MAX_VOLUNTARY_EXITS: usize,
		const SYNC_COMMITTEE_SIZE: usize,
		const BYTES_PER_LOGS_BLOOM: usize,
		const MAX_EXTRA_DATA_BYTES: usize,
		const MAX_BYTES_PER_TRANSACTION: usize,
		const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
		const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
		const MAX_BLS_TO_EXECUTION_CHANGES: usize,
	> ssz_rs::Deserialize
	for BeaconBlockBody<
		MAX_PROPOSER_SLASHINGS,
		MAX_VALIDATORS_PER_COMMITTEE,
		MAX_ATTESTER_SLASHINGS,
		MAX_ATTESTATIONS,
		MAX_DEPOSITS,
		MAX_VOLUNTARY_EXITS,
		SYNC_COMMITTEE_SIZE,
		BYTES_PER_LOGS_BLOOM,
		MAX_EXTRA_DATA_BYTES,
		MAX_BYTES_PER_TRANSACTION,
		MAX_TRANSACTIONS_PER_PAYLOAD,
		MAX_WITHDRAWALS_PER_PAYLOAD,
		MAX_BLS_TO_EXECUTION_CHANGES,
	>
{
	fn deserialize(_encoding: &[u8]) -> Result<Self, DeserializeError>
	where
		Self: Sized,
	{
		panic!("not implemented");
	}
}

impl<
		const MAX_PROPOSER_SLASHINGS: usize,
		const MAX_VALIDATORS_PER_COMMITTEE: usize,
		const MAX_ATTESTER_SLASHINGS: usize,
		const MAX_ATTESTATIONS: usize,
		const MAX_DEPOSITS: usize,
		const MAX_VOLUNTARY_EXITS: usize,
		const SYNC_COMMITTEE_SIZE: usize,
		const BYTES_PER_LOGS_BLOOM: usize,
		const MAX_EXTRA_DATA_BYTES: usize,
		const MAX_BYTES_PER_TRANSACTION: usize,
		const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
		const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
		const MAX_BLS_TO_EXECUTION_CHANGES: usize,
	> ssz_rs::SszReflect
	for BeaconBlockBody<
		MAX_PROPOSER_SLASHINGS,
		MAX_VALIDATORS_PER_COMMITTEE,
		MAX_ATTESTER_SLASHINGS,
		MAX_ATTESTATIONS,
		MAX_DEPOSITS,
		MAX_VOLUNTARY_EXITS,
		SYNC_COMMITTEE_SIZE,
		BYTES_PER_LOGS_BLOOM,
		MAX_EXTRA_DATA_BYTES,
		MAX_BYTES_PER_TRANSACTION,
		MAX_TRANSACTIONS_PER_PAYLOAD,
		MAX_WITHDRAWALS_PER_PAYLOAD,
		MAX_BLS_TO_EXECUTION_CHANGES,
	>
{
	fn ssz_type_class(&self) -> ssz_rs::SszTypeClass {
		match self {
			BeaconBlockBody::Bellatrix(inner) => inner.ssz_type_class(),
			BeaconBlockBody::Capella(inner) => inner.ssz_type_class(),
			BeaconBlockBody::Deneb(inner) => inner.ssz_type_class(),
		}
	}
}

impl<
		const MAX_PROPOSER_SLASHINGS: usize,
		const MAX_VALIDATORS_PER_COMMITTEE: usize,
		const MAX_ATTESTER_SLASHINGS: usize,
		const MAX_ATTESTATIONS: usize,
		const MAX_DEPOSITS: usize,
		const MAX_VOLUNTARY_EXITS: usize,
		const SYNC_COMMITTEE_SIZE: usize,
		const BYTES_PER_LOGS_BLOOM: usize,
		const MAX_EXTRA_DATA_BYTES: usize,
		const MAX_BYTES_PER_TRANSACTION: usize,
		const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
		const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
		const MAX_BLS_TO_EXECUTION_CHANGES: usize,
	> ssz_rs::SimpleSerialize
	for BeaconBlockBody<
		MAX_PROPOSER_SLASHINGS,
		MAX_VALIDATORS_PER_COMMITTEE,
		MAX_ATTESTER_SLASHINGS,
		MAX_ATTESTATIONS,
		MAX_DEPOSITS,
		MAX_VOLUNTARY_EXITS,
		SYNC_COMMITTEE_SIZE,
		BYTES_PER_LOGS_BLOOM,
		MAX_EXTRA_DATA_BYTES,
		MAX_BYTES_PER_TRANSACTION,
		MAX_TRANSACTIONS_PER_PAYLOAD,
		MAX_WITHDRAWALS_PER_PAYLOAD,
		MAX_BLS_TO_EXECUTION_CHANGES,
	>
{
}

#[derive(
	Debug, Clone, Default, SimpleSerialize, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct BeaconBlock<
	const MAX_PROPOSER_SLASHINGS: usize,
	const MAX_VALIDATORS_PER_COMMITTEE: usize,
	const MAX_ATTESTER_SLASHINGS: usize,
	const MAX_ATTESTATIONS: usize,
	const MAX_DEPOSITS: usize,
	const MAX_VOLUNTARY_EXITS: usize,
	const SYNC_COMMITTEE_SIZE: usize,
	const BYTES_PER_LOGS_BLOOM: usize,
	const MAX_EXTRA_DATA_BYTES: usize,
	const MAX_BYTES_PER_TRANSACTION: usize,
	const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
	const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
	const MAX_BLS_TO_EXECUTION_CHANGES: usize,
> {
	#[serde(with = "crate::serde::as_string")]
	pub slot: Slot,
	#[serde(with = "crate::serde::as_string")]
	pub proposer_index: ValidatorIndex,
	pub parent_root: Root,
	pub state_root: Root,
	pub body: BeaconBlockBody<
		MAX_PROPOSER_SLASHINGS,
		MAX_VALIDATORS_PER_COMMITTEE,
		MAX_ATTESTER_SLASHINGS,
		MAX_ATTESTATIONS,
		MAX_DEPOSITS,
		MAX_VOLUNTARY_EXITS,
		SYNC_COMMITTEE_SIZE,
		BYTES_PER_LOGS_BLOOM,
		MAX_EXTRA_DATA_BYTES,
		MAX_BYTES_PER_TRANSACTION,
		MAX_TRANSACTIONS_PER_PAYLOAD,
		MAX_WITHDRAWALS_PER_PAYLOAD,
		MAX_BLS_TO_EXECUTION_CHANGES,
	>,
}

#[derive(
	Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize,
)]
pub struct Fork {
	#[cfg_attr(feature = "serialize", serde(with = "crate::serde::as_hex"))]
	pub previous_version: Version,
	#[cfg_attr(feature = "serialize", serde(with = "crate::serde::as_hex"))]
	pub current_version: Version,
	#[serde(with = "crate::serde::as_string")]
	pub epoch: Epoch,
}

#[derive(Default, Debug, SimpleSerialize, Clone, serde::Deserialize, serde::Serialize)]
pub struct ForkData {
	#[cfg_attr(feature = "serialize", serde(with = "crate::serde::as_hex"))]
	pub current_version: Version,
	pub genesis_validators_root: Root,
}

#[derive(
	Default, Debug, SimpleSerialize, Clone, serde::Deserialize, serde::Serialize, PartialEq, Eq,
)]
pub struct HistoricalSummary {
	pub block_summary_root: Root,
	pub state_summary_root: Root,
}

#[derive(
	Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize,
)]
pub struct BeaconState<
	const SLOTS_PER_HISTORICAL_ROOT: usize,
	const HISTORICAL_ROOTS_LIMIT: usize,
	const ETH1_DATA_VOTES_BOUND: usize,
	const VALIDATOR_REGISTRY_LIMIT: usize,
	const EPOCHS_PER_HISTORICAL_VECTOR: usize,
	const EPOCHS_PER_SLASHINGS_VECTOR: usize,
	const MAX_VALIDATORS_PER_COMMITTEE: usize,
	const SYNC_COMMITTEE_SIZE: usize,
	const BYTES_PER_LOGS_BLOOM: usize,
	const MAX_EXTRA_DATA_BYTES: usize,
	const MAX_BYTES_PER_TRANSACTION: usize,
	const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
> {
	#[serde(with = "crate::serde::as_string")]
	pub genesis_time: u64,
	pub genesis_validators_root: Root,
	#[serde(with = "crate::serde::as_string")]
	pub slot: Slot,
	pub fork: Fork,
	pub latest_block_header: BeaconBlockHeader,
	pub block_roots: Vector<Root, SLOTS_PER_HISTORICAL_ROOT>,
	pub state_roots: Vector<Root, SLOTS_PER_HISTORICAL_ROOT>,
	pub historical_roots: List<Root, HISTORICAL_ROOTS_LIMIT>,
	pub eth1_data: Eth1Data,
	pub eth1_data_votes: List<Eth1Data, ETH1_DATA_VOTES_BOUND>,
	#[serde(with = "crate::serde::as_string")]
	pub eth1_deposit_index: u64,
	pub validators: List<Validator, VALIDATOR_REGISTRY_LIMIT>,
	#[cfg_attr(feature = "serialize", serde(with = "crate::serde::collection_over_string"))]
	pub balances: List<Gwei, VALIDATOR_REGISTRY_LIMIT>,
	pub randao_mixes: Vector<Bytes32, EPOCHS_PER_HISTORICAL_VECTOR>,
	#[cfg_attr(feature = "serialize", serde(with = "crate::serde::collection_over_string"))]
	pub slashings: Vector<Gwei, EPOCHS_PER_SLASHINGS_VECTOR>,
	#[cfg_attr(feature = "serialize", serde(with = "crate::serde::collection_over_string"))]
	pub previous_epoch_participation: List<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT>,
	#[cfg_attr(feature = "serialize", serde(with = "crate::serde::collection_over_string"))]
	pub current_epoch_participation: List<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT>,
	pub justification_bits: Bitvector<JUSTIFICATION_BITS_LENGTH>,
	pub previous_justified_checkpoint: Checkpoint,
	pub current_justified_checkpoint: Checkpoint,
	pub finalized_checkpoint: Checkpoint,
	#[cfg_attr(feature = "serialize", serde(with = "crate::serde::collection_over_string"))]
	pub inactivity_scores: List<u64, VALIDATOR_REGISTRY_LIMIT>,
	pub current_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
	pub next_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
	pub latest_execution_payload_header:
		ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
	#[serde(with = "crate::serde::as_string")]
	pub next_withdrawal_index: WithdrawalIndex,
	#[serde(with = "crate::serde::as_string")]
	pub next_withdrawal_validator_index: ValidatorIndex,
	pub historical_summaries: List<HistoricalSummary, HISTORICAL_ROOTS_LIMIT>,
}
