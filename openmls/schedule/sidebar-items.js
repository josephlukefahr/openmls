initSidebarItems({"enum":[["State",""]],"fn":[["ciphertext_sample",""]],"mod":[["codec",""],["errors",""],["kat_key_schedule","Known Answer Tests for the key scheduleSee https://github.com/mlswg/mls-implementations/blob/master/test-vectors.md for more description on the test vectors."],["psk","Pre shared keys."]],"struct":[["AuthenticationSecret","A secret that can be used among members to make sure everyone has the same group state."],["CommitSecret",""],["ConfirmationKey","The confirmation key is used to calculate the `ConfirmationTag`."],["EncryptionSecret","The `EncryptionSecret` is used to create a `SecretTree`."],["EpochSecret","An intermediate secret in the key schedule, the `EpochSecret` is used to create an `EpochSecrets` object and is finally consumed when creating that epoch's `InitSecret`."],["EpochSecrets","The `EpochSecrets` contain keys (or secrets), which are accessible outside of the `KeySchedule` and which don't get consumed immediately upon first use."],["ExporterSecret","A secret that we can derive secrets from, that are used outside of OpenMLS."],["ExternalSecret","A secret used when joining a group with an external Commit."],["InitSecret","The `InitSecret` is used to connect the next epoch to the current one."],["IntermediateSecret","The intermediate secret includes the optional PSK and is used to later derive the welcome secret and epoch secret"],["JoinerSecret",""],["KeySchedule",""],["MembershipKey","The membership key is used to calculate the `MembershipTag`."],["PreSharedKeyId","A `PreSharedKeyID` is used to uniquely identify the PSKs that get injected in the key schedule."],["PreSharedKeys","`PreSharedKeys` is a vector of `PreSharedKeyID`s. struct { PreSharedKeyID psks<0..2^16-1>; } PreSharedKeys;"],["PskSecret","This contains the `psk-secret` calculated from the PSKs contained in a Commit or a PreSharedKey proposal."],["ResumptionSecret","A secret used in cross-group operations."],["SenderDataSecret","A key that can be used to derive an `AeadKey` and an `AeadNonce`."],["WelcomeSecret",""]]});