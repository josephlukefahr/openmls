use serde::{de::DeserializeOwned, Serialize};

/// The storage version used by OpenMLS
pub const CURRENT_VERSION: u16 = 1;

/// For testing there is a test version defined here.
///
/// THIS VERSION MUST NEVER BE USED OUTSIDE OF TESTS.
#[cfg(feature = "test-utils")]
pub const V_TEST: u16 = u16::MAX;

pub trait StorageProvider<const VERSION: u16> {
    // source for errors
    type Error: core::fmt::Debug + std::error::Error + PartialEq;

    /// Get the version of this provider.
    fn version() -> u16 {
        VERSION
    }

    // Write/queue
    fn queue_proposal<
        GroupId: traits::GroupId<VERSION>,
        ProposalRef: traits::ProposalRef<VERSION>,
        QueuedProposal: traits::QueuedProposal<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<(), Self::Error>;
    fn write_tree<GroupId: traits::GroupId<VERSION>, TreeSync: traits::TreeSync<VERSION>>(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::Error>;
    fn write_interim_transcript_hash<
        GroupId: traits::GroupId<VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::Error>;
    fn write_context<
        GroupId: traits::GroupId<VERSION>,
        GroupContext: traits::GroupContext<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::Error>;
    fn write_confirmation_tag<
        GroupId: traits::GroupId<VERSION>,
        ConfirmationTag: traits::ConfirmationTag<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::Error>;

    // Write crypto objects

    /// Store a signature key.
    ///
    /// Note that signature keys are defined outside of OpenMLS.
    fn write_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
        signature_key_pair: &SignatureKeyPair,
    ) -> Result<(), Self::Error>;

    /// Store an HPKE init private key.
    ///
    /// This is used for init keys from key packages.
    fn write_init_private_key<
        InitKey: traits::InitKey<VERSION>,
        HpkePrivateKey: traits::HpkePrivateKey<VERSION>,
    >(
        &self,
        public_key: &InitKey,
        private_key: &HpkePrivateKey,
    ) -> Result<(), Self::Error>;

    /// Store an HPKE encryption key pair.
    /// This includes the private and public key
    ///
    /// This is used for encryption keys from leaf nodes.
    fn write_encryption_key_pair<
        EncryptionKey: traits::EncryptionKey<VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
        key_pair: &HpkeKeyPair,
    ) -> Result<(), Self::Error>;

    /// Store a list of HPKE encryption key pairs for a given epoch.
    /// This includes the private and public keys.
    fn write_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<VERSION>,
        EpochKey: traits::EpochKey<VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
        key_pairs: &[HpkeKeyPair],
    ) -> Result<(), Self::Error>;

    /// Store key packages.
    ///
    /// Store a key package. This does not include the private keys. They are
    /// stored separately with `write_hpke_private_key`.
    fn write_key_package<
        HashReference: traits::HashReference<VERSION>,
        KeyPackage: traits::KeyPackage<VERSION>,
    >(
        &self,
        hash_ref: &HashReference,
        key_package: &KeyPackage,
    ) -> Result<(), Self::Error>;

    /// Store a PSK.
    ///
    /// This stores PSKs based on the PSK id.
    fn write_psk<PskId: traits::PskId<VERSION>, PskBundle: traits::PskBundle<VERSION>>(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> Result<(), Self::Error>;

    // getter
    /// Returns references of all queued proposals, or an empty vector of none are stored.
    fn queued_proposal_refs<
        GroupId: traits::GroupId<VERSION>,
        ProposalRef: traits::ProposalRef<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, Self::Error>;

    /// Returns all queued proposals, or an empty vector of none are stored.
    fn queued_proposals<
        GroupId: traits::GroupId<VERSION>,
        QueuedProposal: traits::QueuedProposal<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<QueuedProposal>, Self::Error>;

    fn treesync<GroupId: traits::GroupId<VERSION>, TreeSync: traits::TreeSync<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::Error>;

    fn group_context<
        GroupId: traits::GroupId<VERSION>,
        GroupContext: traits::GroupContext<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::Error>;

    fn interim_transcript_hash<
        GroupId: traits::GroupId<VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::Error>;

    fn confirmation_tag<
        GroupId: traits::GroupId<VERSION>,
        ConfirmationTag: traits::ConfirmationTag<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::Error>;

    // Get crypto objects

    /// Get a signature key based on the public key.
    fn signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPair>, Self::Error>;

    /// Get a private init key based on the corresponding public kye.
    fn init_private_key<
        InitKey: traits::InitKey<VERSION>,
        HpkePrivateKey: traits::HpkePrivateKey<VERSION>,
    >(
        &self,
        public_key: &InitKey,
    ) -> Result<Option<HpkePrivateKey>, Self::Error>;

    /// Get an HPKE encryption key pair based on the public key.
    fn encryption_key_pair<
        HpkeKeyPair: traits::HpkeKeyPair<VERSION>,
        EncryptionKey: traits::EncryptionKey<VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<Option<HpkeKeyPair>, Self::Error>;

    /// Get a list of HPKE encryption key pairs for a given epoch.
    /// This includes the private and public keys.
    fn encryption_epoch_key_pairs<
        GroupId: traits::GroupId<VERSION>,
        EpochKey: traits::EpochKey<VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<Vec<HpkeKeyPair>, Self::Error>;

    /// Get a key package based on its hash reference.
    fn key_package<
        KeyPackageRef: traits::HashReference<VERSION>,
        KeyPackage: traits::KeyPackage<VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, Self::Error>;

    /// Get a PSK based on the PSK identifier.
    fn psk<PskBundle: traits::PskBundle<VERSION>, PskId: traits::PskId<VERSION>>(
        &self,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, Self::Error>;

    // Delete crypto objects

    /// Delete a signature key pair based on its public key
    fn delete_signature_key_pair<SignaturePublicKeuy: traits::SignaturePublicKey<VERSION>>(
        &self,
        public_key: &SignaturePublicKeuy,
    ) -> Result<(), Self::Error>;

    /// Delete an HPKE private init key.
    ///
    /// XXX: traits::This should be called when deleting key packages.
    fn delete_init_private_key<InitKey: traits::InitKey<VERSION>>(
        &self,
        public_key: &InitKey,
    ) -> Result<(), Self::Error>;

    /// Delete an encryption key pair for a public key.
    fn delete_encryption_key_pair<EncryptionKey: traits::EncryptionKey<VERSION>>(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<(), Self::Error>;

    /// Delete a list of HPKE encryption key pairs for a given epoch.
    /// This includes the private and public keys.
    fn delete_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<VERSION>,
        EpochKey: traits::EpochKey<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<(), Self::Error>;

    /// Delete a key package based on the hash reference.
    ///
    /// XXX: traits::This needs to delete all corresponding keys.
    fn delete_key_package<KeyPackageRef: traits::HashReference<VERSION>>(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<(), Self::Error>;

    /// Delete a PSK based on an identifier.
    fn delete_psk<PskKey: traits::PskId<VERSION>>(
        &self,
        psk_id: &PskKey,
    ) -> Result<(), Self::Error>;

    /// Returns the MlsGroupState for group with given id.
    fn group_state<GroupState: traits::GroupState<VERSION>, GroupId: traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupState>, Self::Error>;

    /// Writes the MlsGroupState for group with given id.
    fn write_group_state<
        GroupState: traits::GroupState<VERSION>,
        GroupId: traits::GroupId<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_state: &GroupState,
    ) -> Result<(), Self::Error>;

    /// Deletes the MlsGroupState for group with given id.
    fn delete_group_state<GroupId: traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error>;

    /// Returns the MessageSecretsStore for the group with the given id.
    fn message_secrets<
        GroupId: traits::GroupId<VERSION>,
        MessageSecrets: traits::MessageSecrets<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MessageSecrets>, Self::Error>;

    /// Writes the MessageSecretsStore for the group with the given id.
    fn write_message_secrets<
        GroupId: traits::GroupId<VERSION>,
        MessageSecrets: traits::MessageSecrets<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> Result<(), Self::Error>;

    /// Deletes the MessageSecretsStore for the group with the given id.
    fn delete_message_secrets<GroupId: traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error>;

    /// Returns the ResumptionPskStore for the group with the given id.
    fn resumption_psk_store<
        GroupId: traits::GroupId<VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ResumptionPskStore>, Self::Error>;

    /// Writes the ResumptionPskStore for the group with the given id.
    fn write_resumption_psk_store<
        GroupId: traits::GroupId<VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        resumption_psk_store: &ResumptionPskStore,
    ) -> Result<(), Self::Error>;

    /// Deletes the ResumptionPskStore for the group with the given id.
    fn delete_all_resumption_psk_secrets<GroupId: traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error>;

    /// Returns the own leaf index inside the group for the group with the given id.
    fn own_leaf_index<
        GroupId: traits::GroupId<VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<LeafNodeIndex>, Self::Error>;

    /// Writes the own leaf index inside the group for the group with the given id.
    fn write_own_leaf_index<
        GroupId: traits::GroupId<VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        own_leaf_index: &LeafNodeIndex,
    ) -> Result<(), Self::Error>;

    /// Deletes the own leaf index inside the group for the group with the given id.
    fn delete_own_leaf_index<GroupId: traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error>;

    /// Returns whether to use the RatchetTreeExtension for the group with the given id.
    fn use_ratchet_tree_extension<GroupId: traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<bool>, Self::Error>;

    /// Sets whether to use the RatchetTreeExtension for the group with the given id.
    fn set_use_ratchet_tree_extension<GroupId: traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
        value: bool,
    ) -> Result<(), Self::Error>;

    /// Deletes any preference about whether to use the RatchetTreeExtension for the group with the given id.
    fn delete_use_ratchet_tree_extension<GroupId: traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error>;

    /// Returns the GroupEpochSecrets for the group with the given id.
    fn group_epoch_secrets<
        GroupId: traits::GroupId<VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupEpochSecrets>, Self::Error>;

    /// Writes the GroupEpochSecrets for the group with the given id.
    fn write_group_epoch_secrets<
        GroupId: traits::GroupId<VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::Error>;

    /// Deletes the GroupEpochSecrets for the group with the given id.
    fn delete_group_epoch_secrets<GroupId: traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error>;
}

// base traits for keys and values
pub trait Key<const VERSION: u16>: Serialize {}
pub trait Entity<const VERSION: u16>: Serialize + DeserializeOwned {}

// in the following we define specific traits for Keys and Entities. That way
// we can don't sacrifice type safety in the implementations of the storage provider.
// note that there are types that are used both as keys and as entities.

pub mod traits {
    use super::{Entity, Key};

    // traits for keys, one per data type
    pub trait GroupId<const VERSION: u16>: Key<VERSION> {}
    pub trait ProposalRefKey<const VERSION: u16>: Key<VERSION> {}
    pub trait SignaturePublicKey<const VERSION: u16>: Key<VERSION> {}
    pub trait InitKey<const VERSION: u16>: Key<VERSION> {}
    pub trait HashReference<const VERSION: u16>: Key<VERSION> {}
    pub trait PskId<const VERSION: u16>: Key<VERSION> {}
    pub trait EncryptionKey<const VERSION: u16>: Key<VERSION> {}
    pub trait EpochKey<const VERSION: u16>: Key<VERSION> {}

    // traits for entity, one per type
    pub trait QueuedProposal<const VERSION: u16>: Entity<VERSION> {}
    pub trait ProposalRef<const VERSION: u16>: Entity<VERSION> {}
    pub trait TreeSync<const VERSION: u16>: Entity<VERSION> {}
    pub trait GroupContext<const VERSION: u16>: Entity<VERSION> {}
    pub trait InterimTranscriptHash<const VERSION: u16>: Entity<VERSION> {}
    pub trait ConfirmationTag<const VERSION: u16>: Entity<VERSION> {}
    pub trait SignatureKeyPair<const VERSION: u16>: Entity<VERSION> {}
    pub trait HpkePrivateKey<const VERSION: u16>: Entity<VERSION> {}
    pub trait PskBundle<const VERSION: u16>: Entity<VERSION> {}
    pub trait HpkeKeyPair<const VERSION: u16>: Entity<VERSION> {}
    pub trait GroupState<const VERSION: u16>: Entity<VERSION> {}
    pub trait GroupEpochSecrets<const VERSION: u16>: Entity<VERSION> {}
    pub trait LeafNodeIndex<const VERSION: u16>: Entity<VERSION> {}
    pub trait GroupUseRatchetTreeExtension<const VERSION: u16>: Entity<VERSION> {}
    pub trait MessageSecrets<const VERSION: u16>: Entity<VERSION> {}
    pub trait ResumptionPskStore<const VERSION: u16>: Entity<VERSION> {}
    pub trait KeyPackage<const VERSION: u16>: Entity<VERSION> {}
}
