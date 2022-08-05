import copy
import datetime
import logging
from typing import Dict, List

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from localstack.aws.api import CommonServiceException, RequestContext, handler
from localstack.aws.api.kms import (
    AlgorithmSpec,
    AlreadyExistsException,
    CancelKeyDeletionRequest,
    CancelKeyDeletionResponse,
    CiphertextType,
    CreateAliasRequest,
    CreateGrantRequest,
    CreateGrantResponse,
    CreateKeyRequest,
    CreateKeyResponse,
    DateType,
    DecryptResponse,
    DeleteAliasRequest,
    DescribeKeyRequest,
    DescribeKeyResponse,
    DisableKeyRequest,
    DisableKeyRotationRequest,
    EnableKeyRequest,
    EncryptionAlgorithmSpec,
    EncryptionContextType,
    EncryptResponse,
    ExpirationModelType,
    GenerateDataKeyPairRequest,
    GenerateDataKeyPairResponse,
    GenerateDataKeyPairWithoutPlaintextRequest,
    GenerateDataKeyPairWithoutPlaintextResponse,
    GetKeyPolicyRequest,
    GetKeyPolicyResponse,
    GetKeyRotationStatusRequest,
    GetKeyRotationStatusResponse,
    GetParametersForImportResponse,
    GetPublicKeyResponse,
    GrantIdType,
    GrantTokenList,
    GrantTokenType,
    ImportKeyMaterialResponse,
    InvalidCiphertextException,
    InvalidGrantIdException,
    InvalidKeyUsageException,
    KeyIdType,
    KmsApi,
    KMSInvalidStateException,
    LimitType,
    ListAliasesResponse,
    ListGrantsRequest,
    ListGrantsResponse,
    ListKeyPoliciesRequest,
    ListKeyPoliciesResponse,
    ListKeysRequest,
    ListKeysResponse,
    ListResourceTagsRequest,
    ListResourceTagsResponse,
    MarkerType,
    NotFoundException,
    PlaintextType,
    PrincipalIdType,
    PutKeyPolicyRequest,
    ReplicateKeyRequest,
    ReplicateKeyResponse,
    ScheduleKeyDeletionRequest,
    ScheduleKeyDeletionResponse,
    SignRequest,
    SignResponse,
    TagResourceRequest,
    UnsupportedOperationException,
    UntagResourceRequest,
    UpdateKeyDescriptionRequest,
    VerifyRequest,
    VerifyResponse,
    WrappingKeySpec,
)
from localstack.services.generic_proxy import RegionBackend
from localstack.services.kms.models import (
    KeyImportState,
    KmsAlias,
    KmsCryptoKey,
    KmsGrant,
    KmsKey,
    KmsStore,
    ValidationException,
    deserialize_ciphertext_blob,
    get_key_id_from_any_id,
    kms_stores,
)
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.aws.aws_stack import kms_alias_arn
from localstack.utils.collections import PaginatedList
from localstack.utils.common import select_attributes
from localstack.utils.strings import short_uid, to_bytes, to_str

LOG = logging.getLogger(__name__)


# valid operations
VALID_OPERATIONS = [
    "CreateKey",
    "Decrypt",
    "Encrypt",
    "GenerateDataKey",
    "GenerateDataKeyWithoutPlaintext",
    "ReEncryptFrom",
    "ReEncryptTo",
    "Sign",
    "Verify",
    "GetPublicKey",
    "CreateGrant",
    "RetireGrant",
    "DescribeKey",
    "GenerateDataKeyPair",
    "GenerateDataKeyPairWithoutPlaintext",
]

# grant attributes
KEY_ID = "KeyId"
GRANTEE_PRINCIPAL = "GranteePrincipal"
RETIRING_PRINCIPAL = "RetiringPrincipal"
OPERATIONS = "Operations"
GRANT_ID = "GrantId"
GRANT_TOKENS = "GrantTokens"
NAME = "Name"
CONSTRAINTS = "Constraints"
ISSUING_ACCOUNT = "IssuingAccount"
CREATION_DATE = "CreationDate"


# TODO The backend is no longer in use. But before we remove it from this code, have to update localstack-ext to switch
#  persistence from the backend to the new stores.
class KMSBackend(RegionBackend):
    # maps grant ID to grant details
    grants: Dict[str, Dict]
    # maps pagination markers to result lists
    markers: Dict[str, List]
    # maps key ID to keypair details
    key_pairs: Dict[str, Dict]
    # maps import tokens to import states
    imports: Dict[str, KeyImportState]

    def __init__(self):
        self.grants = {}
        self.markers = {}
        self.key_pairs = {}
        self.imports = {}


class ValidationError(CommonServiceException):
    """General validation error type (defined in the AWS docs, but not part of the botocore spec)"""

    def __init__(self, message=None):
        super().__init__("ValidationError", message=message)


def _verify_key_exists(key_id, store: KmsStore):
    if key_id not in store.keys:
        raise NotFoundException(f"Invalid keyID '{key_id}'")


def _get_key(any_type_of_key_id: str, store: KmsStore) -> KmsKey:
    key_id = get_key_id_from_any_id(any_type_of_key_id, store)
    _verify_key_exists(key_id, store)
    return store.keys[key_id]


class KmsProvider(KmsApi, ServiceLifecycleHook):
    def _get_store(self, context: RequestContext) -> KmsStore:
        return kms_stores[context.account_id][context.region]

    @handler("CreateKey", expand=False)
    def create_key(
        self,
        context: RequestContext,
        create_key_request: CreateKeyRequest = None,
    ) -> CreateKeyResponse:
        key = KmsKey(create_key_request, context.account_id, context.region)
        key_id = key.metadata.get("KeyId")
        self._get_store(context).keys[key_id] = key
        return CreateKeyResponse(KeyMetadata=key.metadata)

    @handler("ScheduleKeyDeletion", expand=False)
    def schedule_key_deletion(
        self, context: RequestContext, schedule_key_deletion_request: ScheduleKeyDeletionRequest
    ) -> ScheduleKeyDeletionResponse:
        pending_window = int(schedule_key_deletion_request.get("PendingWindowInDays", 30))
        if pending_window < 7 or pending_window > 30:
            raise ValidationException(
                f"PendingWindowInDays should be between 7 and 30, but it is {pending_window}"
            )
        key = _get_key(schedule_key_deletion_request.get("KeyId"), self._get_store(context))
        key.schedule_key_deletion(pending_window)
        attrs = ["DeletionDate", "KeyId", "KeyState"]
        result = select_attributes(key.metadata, attrs)
        result["PendingWindowInDays"] = pending_window
        return ScheduleKeyDeletionResponse(**result)

    @handler("CancelKeyDeletion", expand=False)
    def cancel_key_deletion(
        self, context: RequestContext, cancel_key_deletion_request: CancelKeyDeletionRequest
    ) -> CancelKeyDeletionResponse:
        key = _get_key(cancel_key_deletion_request.get("KeyId"), self._get_store(context))
        key.metadata["KeyState"] = "Disabled"
        key.metadata["DeletionDate"] = None
        # https://docs.aws.amazon.com/kms/latest/APIReference/API_CancelKeyDeletion.html#API_CancelKeyDeletion_ResponseElements
        # "The Amazon Resource Name (key ARN) of the KMS key whose deletion is canceled."
        return CancelKeyDeletionResponse(KeyId=key.metadata.get("Arn"))

    @handler("DisableKey", expand=False)
    def disable_key(self, context: RequestContext, disable_key_request: DisableKeyRequest) -> None:
        key = _get_key(disable_key_request.get("KeyId"), self._get_store(context))
        key.metadata["KeyState"] = "Disabled"
        key.metadata["Enabled"] = False

    @handler("EnableKey", expand=False)
    def enable_key(self, context: RequestContext, enable_key_request: EnableKeyRequest) -> None:
        key = _get_key(enable_key_request.get("KeyId"), self._get_store(context))
        key.metadata["KeyState"] = "Enabled"
        key.metadata["Enabled"] = True

    @handler("ListKeys", expand=False)
    def list_keys(
        self, context: RequestContext, list_keys_request: ListKeysRequest
    ) -> ListKeysResponse:
        # https://docs.aws.amazon.com/kms/latest/APIReference/API_ListKeys.html#API_ListKeys_ResponseSyntax
        # Out of whole KeyMetadata only two fields are present in the response.
        keys_list = PaginatedList(
            [
                {"KeyArn": key.metadata.get("KeyArn"), "KeyId": key.metadata.get("KeyId")}
                for key in self._get_store(context).keys.values()
            ]
        )
        page, next_token = keys_list.get_page(
            lambda key_data: key_data.get("KeyId"),
            next_token=list_keys_request.get("Marker"),
            page_size=list_keys_request.get("Limit", 100),
        )
        kwargs = {"NextMarker": next_token, "Truncated": True} if next_token else {}
        return ListKeysResponse(Keys=page, **kwargs)

    @handler("DescribeKey", expand=False)
    def describe_key(
        self, context: RequestContext, describe_key_request: DescribeKeyRequest
    ) -> DescribeKeyResponse:
        key = _get_key(describe_key_request.get("KeyId"), self._get_store(context))
        return DescribeKeyResponse(KeyMetadata=key.metadata)

    @handler("ReplicateKey", expand=False)
    def replicate_key(
        self, context: RequestContext, replicate_key_request: ReplicateKeyRequest
    ) -> ReplicateKeyResponse:
        replicate_from_store = self._get_store(context)
        key = _get_key(replicate_key_request.get("KeyId"), replicate_from_store)
        key_id = key.metadata.get("KeyId")
        if not key.metadata.get("MultiRegion"):
            raise UnsupportedOperationException(
                f"Unable to replicate a non-MultiRegion key {key_id}"
            )
        replica_region = replicate_key_request.get("ReplicaRegion")
        replicate_to_store = kms_stores[context.account_id][replica_region]
        if key_id in replicate_to_store.keys:
            raise AlreadyExistsException(
                f"Unable to replicate key {key_id} to region {replica_region}, as the key "
                f"already exist there"
            )
        replica_key = copy.deepcopy(key)
        if replicate_key_request.get("Description"):
            replica_key.metadata["Description"] = replicate_key_request.get("Description")
        replicate_to_store.keys[key_id] = replica_key

    @handler("UpdateKeyDescription", expand=False)
    def update_key_description(
        self, context: RequestContext, update_key_description_request: UpdateKeyDescriptionRequest
    ) -> None:
        key = _get_key(update_key_description_request.get("KeyId"), self._get_store(context))
        key.metadata["Description"] = update_key_description_request.get("Description")

    # TODO If there is an attempt to create a grant for a key pending deletion, the following error is generated in AWS:
    #      KMSInvalidStateException("<KEY ARN> is pending deletion")
    #  Should implement that in LocalStack as well.
    @handler("CreateGrant", expand=False)
    def create_grant(
        self, context: RequestContext, create_grant_request: CreateGrantRequest
    ) -> CreateGrantResponse:
        store = self._get_store(context)
        # KeyId can potentially hold one of multiple different types of key identifiers. _get_key finds a key no
        # matter which type of id is used.
        create_grant_request["KeyId"] = _get_key(create_grant_request.get("KeyId"), store).metadata[
            "KeyId"
        ]
        self._validate_grant_request(create_grant_request, store)
        grant_name = create_grant_request.get("Name")
        grant = None
        if grant_name and grant_name in store.grant_names:
            grant = store.grants[store.grant_names[grant_name]]
        else:
            grant = KmsGrant(create_grant_request)
            grant_id = grant.metadata["GrantId"]
            store.grants[grant_id] = grant
            if grant_name:
                store.grant_names[grant_name] = grant_id
            store.grant_tokens[grant.token] = grant_id

        # At the moment we do not support multiple GrantTokens for grant creation request. Instead, we always use
        # the same token. For the reference, AWS documentation says:
        # https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateGrant.html#API_CreateGrant_RequestParameters
        # "The returned grant token is unique with every CreateGrant request, even when a duplicate GrantId is
        # returned". "A duplicate GrantId" refers to the idempotency of grant creation requests - if a request has
        # "Name" field, and if such name already belongs to a previously created grant, no new grant gets created
        # and the existing grant with the name is returned.
        return CreateGrantResponse(GrantId=grant.metadata["GrantId"], GrantToken=grant.token)

    @handler("ListGrants", expand=False)
    def list_grants(
        self, context: RequestContext, list_grants_request: ListGrantsRequest
    ) -> ListGrantsResponse:
        if not list_grants_request.get("KeyId"):
            raise ValidationError("Required input parameter KeyId not specified")
        store = self._get_store(context)
        # KeyId can potentially hold one of multiple different types of key identifiers. _get_key finds a key no
        # matter which type of id is used.
        key_id = _get_key(list_grants_request.get("KeyId"), self._get_store(context)).metadata[
            "KeyId"
        ]

        grant_id = list_grants_request.get("GrantId")
        if grant_id:
            if grant_id not in store.grants:
                raise InvalidGrantIdException()
            return ListGrantsResponse(Grants=[store.grants[grant_id].metadata])

        matching_grants = []
        grantee_principal = list_grants_request.get("GranteePrincipal")
        for grant in store.grants.values():
            # KeyId is a mandatory field of ListGrants request, so is going to be present.
            if grant.metadata["KeyId"] != key_id:
                continue
            # GranteePrincipal is a mandatory field for CreateGrant, should be in grants. But it is an optional field
            # for ListGrants, so might not be there.
            if grantee_principal and grant.metadata["GranteePrincipal"] != grantee_principal:
                continue
            matching_grants.append(grant.metadata)

        grants_list = PaginatedList(matching_grants)
        page, next_token = grants_list.get_page(
            lambda grant_data: grant_data.get("GrantId"),
            next_token=list_grants_request.get("Marker"),
            page_size=list_grants_request.get("Limit", 50),
        )
        kwargs = {"NextMarker": next_token, "Truncated": True} if next_token else {}

        return ListGrantsResponse(Grants=page, **kwargs)

    # Honestly, this is a mess in AWS KMS. Hashtag "do we follow specifications that are a pain to customers or do we
    # diverge from AWS and make the life of our customers easier?"
    #
    # Both RetireGrant and RevokeGrant operations delete a grant. The differences between them are described here:
    # https://docs.aws.amazon.com/kms/latest/developerguide/grant-manage.html#grant-delete
    # Essentially:
    # - Permissions to RevokeGrant are controlled through IAM policies or through key policies, while permissions to
    # RetireGrant are controlled by settings inside the grant itself.
    # - A grant to be retired can be specified by its GrantToken or its GrantId/KeyId pair. While revoking grants can
    # only be done with a GrantId/KeyId pair.
    # - For RevokeGrant, KeyId can be either an actual key ID, or an ARN of that key. While for RetireGrant only key
    # ARN is accepted as a KeyId.
    #
    # We currently do not model permissions for retirement and revocation of grants. At least not in KMS,
    # maybe IAM in LocalStack has some modelling though. We also accept both key IDs and key ARNs for both
    # operations. So apart from RevokeGrant not accepting GrantToken parameter, we treat these two operations the same.
    def _delete_grant(
        self, store: KmsStore, grant_id: str = None, key_id: str = None, grant_token: str = None
    ):
        if grant_token:
            if grant_token not in store.grant_tokens:
                raise NotFoundException(f"Unable to find grant token {grant_token}")
            grant_id = store.grant_tokens[grant_token]
            # Do not really care about the key ID if a grant is identified by a token. But since a key has to be
            # validated when a grant is identified by GrantId/KeyId pair, and since we want to use the same code in
            # both cases - when we have a grant token or a GrantId/KeyId pair - have to set key_id.
            key_id = store.grants[grant_id].metadata["KeyId"]

        # KeyId can potentially hold one of multiple different types of key identifiers. _get_key finds a key no
        # matter which type of id is used.
        key_id = _get_key(key_id, store).metadata["KeyId"]
        if grant_id not in store.grants:
            raise InvalidGrantIdException()
        if store.grants[grant_id].metadata["KeyId"] != key_id:
            raise ValidationError(f"Invalid KeyId={key_id} specified for grant {grant_id}")

        grant = store.grants[grant_id]
        # In AWS grants have one or more tokens. But we have a simplified modeling of grants, where they have exactly
        # one token.
        store.grant_tokens.pop(grant.token)
        store.grant_names.pop(grant.metadata.get("Name"), None)
        store.grants.pop(grant_id)

    @handler("RevokeGrant")
    def revoke_grant(
        self, context: RequestContext, key_id: KeyIdType, grant_id: GrantIdType
    ) -> None:
        self._delete_grant(store=self._get_store(context), grant_id=grant_id, key_id=key_id)

    @handler("RetireGrant")
    def retire_grant(
        self,
        context: RequestContext,
        grant_token: GrantTokenType = None,
        key_id: KeyIdType = None,
        grant_id: GrantIdType = None,
    ) -> None:
        if not grant_token and (not grant_id or not key_id):
            raise ValidationException("Grant token OR (grant ID, key ID) must be specified")
        self._delete_grant(
            store=self._get_store(context),
            grant_id=grant_id,
            key_id=key_id,
            grant_token=grant_token,
        )

    @handler("ListRetirableGrants")
    def list_retirable_grants(
        self,
        context: RequestContext,
        retiring_principal: PrincipalIdType,
        limit: LimitType = None,
        marker: MarkerType = None,
    ) -> ListGrantsResponse:
        if not retiring_principal:
            raise ValidationError(f"Required input parameter '{RETIRING_PRINCIPAL}' not specified")

        matching_grants = [
            grant.metadata
            for grant in self._get_store(context).grants.values()
            if grant.metadata.get("RetiringPrincipal") == retiring_principal
        ]
        grants_list = PaginatedList(matching_grants)
        limit = limit or 50
        page, next_token = grants_list.get_page(
            lambda grant_data: grant_data.get("GrantId"),
            next_token=marker,
            page_size=limit,
        )
        kwargs = {"NextMarker": next_token, "Truncated": True} if next_token else {}

        return ListGrantsResponse(Grants=page, **kwargs)

    @handler("GetPublicKey")
    def get_public_key(
        self, context: RequestContext, key_id: KeyIdType, grant_tokens: GrantTokenList = None
    ) -> GetPublicKeyResponse:
        key = _get_key(key_id, self._get_store(context))
        attrs = [
            "KeySpec",
            "KeyUsage",
            "EncryptionAlgorithms",
            "SigningAlgorithms",
        ]
        result = select_attributes(key.metadata, attrs)
        result["PublicKey"] = key.crypto_key.public_key
        result["KeyId"] = key.metadata["Arn"]
        return GetPublicKeyResponse(**result)

    def _generate_data_key_pair(self, key_id: str, key_pair_spec: str, context: RequestContext):
        key = _get_key(key_id, self._get_store(context))
        self._validate_key_for_encryption_decryption(key)
        crypto_key = KmsCryptoKey(key_pair_spec)
        return {
            "KeyId": key_id,
            "KeyPairSpec": key_pair_spec,
            "PrivateKeyCiphertextBlob": key.encrypt(crypto_key.private_key),
            "PrivateKeyPlaintext": crypto_key.private_key,
            "PublicKey": crypto_key.public_key,
        }

    @handler("GenerateDataKeyPair", expand=False)
    def generate_data_key_pair(
        self,
        context: RequestContext,
        generate_data_key_pair_request: GenerateDataKeyPairRequest,
    ) -> GenerateDataKeyPairResponse:
        result = self._generate_data_key_pair(
            generate_data_key_pair_request.get("KeyId"),
            generate_data_key_pair_request.get("KeyPairSpec"),
            context,
        )
        return GenerateDataKeyPairResponse(**result)

    @handler("GenerateDataKeyPairWithoutPlaintext", expand=False)
    def generate_data_key_pair_without_plaintext(
        self,
        context: RequestContext,
        generate_data_key_pair_without_plaintext_request: GenerateDataKeyPairWithoutPlaintextRequest,
    ) -> GenerateDataKeyPairWithoutPlaintextResponse:
        result = self._generate_data_key_pair(
            generate_data_key_pair_without_plaintext_request.get("KeyId"),
            generate_data_key_pair_without_plaintext_request.get("KeyPairSpec"),
            context,
        )
        result.pop("PrivateKeyPlaintext")
        return GenerateDataKeyPairResponse(**result)

    @handler("Sign", expand=False)
    def sign(self, context: RequestContext, sign_request: SignRequest) -> SignResponse:
        key = _get_key(sign_request.get("KeyId"), self._get_store(context))
        self._validate_key_for_sign_verify(key)

        # TODO Add constraints on KeySpec / SigningAlgorithm pairs:
        #  https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html#key-spec-ecc

        signing_algorithm = sign_request.get("SigningAlgorithm")
        signature = key.sign(sign_request.get("Message"), signing_algorithm)

        result = {
            "KeyId": key.metadata["KeyId"],
            "Signature": signature,
            "SigningAlgorithm": signing_algorithm,
        }
        return SignResponse(**result)

    @handler("Verify", expand=False)
    def verify(self, context: RequestContext, verify_request: VerifyRequest) -> VerifyResponse:
        key = _get_key(verify_request.get("KeyId"), self._get_store(context))
        self._validate_key_for_sign_verify(key)

        signing_algorithm = verify_request.get("SigningAlgorithm")
        is_signature_valid = key.verify(
            verify_request.get("Message"), signing_algorithm, verify_request.get("Signature")
        )

        result = {
            "KeyId": key.metadata["KeyId"],
            "SignatureValid": is_signature_valid,
            "SigningAlgorithm": signing_algorithm,
        }
        return VerifyResponse(**result)

    def encrypt(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        plaintext: PlaintextType,
        encryption_context: EncryptionContextType = None,
        grant_tokens: GrantTokenList = None,
        encryption_algorithm: EncryptionAlgorithmSpec = None,
    ) -> EncryptResponse:
        key = _get_key(key_id, self._get_store(context))
        self._validate_key_for_encryption_decryption(key)
        encryption_context = encryption_context or {}

        ciphertext_blob = key.encrypt(plaintext, encryption_context)
        # For compatibility, we return EncryptionAlgorithm values expected from AWS. But LocalStack currently always
        # encrypts with symmetric encryption no matter the key settings.
        return EncryptResponse(
            CiphertextBlob=ciphertext_blob, KeyId=key_id, EncryptionAlgorithm=encryption_algorithm
        )

    def decrypt(
        self,
        context: RequestContext,
        ciphertext_blob: CiphertextType,
        encryption_context: EncryptionContextType = None,
        grant_tokens: GrantTokenList = None,
        key_id: KeyIdType = None,
        encryption_algorithm: EncryptionAlgorithmSpec = None,
    ) -> DecryptResponse:
        # In AWS, key_id is only supplied for data encrypted with an asymmetrical algorithm. For symmetrical
        # encryption, key_id is taken from the encrypted data itself.
        # Since LocalStack doesn't currently do asymmetrical encryption, there is a question of modeling here: we
        # currently expect data to be only encrypted with symmetric encryption, so having key_id inside. It might not
        # always be what customers expect.
        try:
            ciphertext = deserialize_ciphertext_blob(ciphertext_blob=ciphertext_blob)
        except Exception:
            raise InvalidCiphertextException(
                "LocalStack is unable to deserialize the ciphertext blob. Perhaps the "
                "blob didn't come from LocalStack"
            )
        store = self._get_store(context)
        key_id = get_key_id_from_any_id(key_id, store)
        if key_id and key_id != ciphertext.key_id:
            # Haven't checked if this is the exception being raised by AWS in such cases.
            ValidationError(
                f"The supplied KeyId {key_id} doesn't match the KeyId {ciphertext.key_id} present in "
                f"ciphertext. Keep in mind that LocalStack currently doesn't perform asymmetric encryption"
            )
        key_id = ciphertext.key_id
        key = _get_key(key_id, self._get_store(context))
        self._validate_key_for_encryption_decryption(key)
        encryption_context = encryption_context or {}

        plaintext = key.decrypt(ciphertext, encryption_context)
        # For compatibility, we return EncryptionAlgorithm values expected from AWS. But LocalStack currently always
        # encrypts with symmetric encryption no matter the key settings.
        return DecryptResponse(
            KeyId=key_id, Plaintext=plaintext, EncryptionAlgorithm=encryption_algorithm
        )

    def get_parameters_for_import(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        wrapping_algorithm: AlgorithmSpec,
        wrapping_key_spec: WrappingKeySpec,
    ) -> GetParametersForImportResponse:
        store = self._get_store(context)
        # KeyId can potentially hold one of multiple different types of key identifiers. _get_key finds a key no
        # matter which type of id is used.
        key_to_import_material_to = _get_key(key_id, store)
        if key_to_import_material_to.metadata.get("Origin") != "EXTERNAL":
            raise UnsupportedOperationException(
                "Key material can only be imported into keys with Origin of EXTERNAL"
            )
        self._validate_key_for_encryption_decryption(key_to_import_material_to)
        key_id = key_to_import_material_to.metadata["KeyId"]

        key = KmsKey(CreateKeyRequest(KeySpec=wrapping_key_spec))
        import_token = short_uid()
        import_state = KeyImportState(
            key_id=key_id, import_token=import_token, wrapping_algo=wrapping_algorithm, key=key
        )
        store.imports[import_token] = import_state
        # https://docs.aws.amazon.com/kms/latest/APIReference/API_GetParametersForImport.html
        # "To import key material, you must use the public key and import token from the same response. These items
        # are valid for 24 hours."
        expiry_date = datetime.datetime.now() + datetime.timedelta(days=100)
        return GetParametersForImportResponse(
            KeyId=key_to_import_material_to.metadata["Arn"],
            ImportToken=to_bytes(import_state.import_token),
            PublicKey=import_state.key.crypto_key.public_key,
            ParametersValidTo=expiry_date,
        )

    def import_key_material(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        import_token: CiphertextType,
        encrypted_key_material: CiphertextType,
        valid_to: DateType = None,
        expiration_model: ExpirationModelType = None,
    ) -> ImportKeyMaterialResponse:
        store = self._get_store(context)
        import_token = to_str(import_token)
        import_state = store.imports.get(import_token)
        if not import_state:
            raise NotFoundException(f"Unable to find key import token '{import_token}'")
        # KeyId can potentially hold one of multiple different types of key identifiers. _get_key finds a key no
        # matter which type of id is used.
        key_to_import_material_to = _get_key(key_id, store)
        self._validate_key_for_encryption_decryption(key_to_import_material_to)

        if import_state.wrapping_algo == AlgorithmSpec.RSAES_PKCS1_V1_5:
            decrypt_padding = padding.PKCS1v15()
        elif import_state.wrapping_algo == AlgorithmSpec.RSAES_OAEP_SHA_1:
            decrypt_padding = padding.OAEP(padding.MGF1(hashes.SHA1()), hashes.SHA1(), None)
        elif import_state.wrapping_algo == AlgorithmSpec.RSAES_OAEP_SHA_256:
            decrypt_padding = padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)
        else:
            raise KMSInvalidStateException(
                f"Unsupported padding, requested wrapping algorithm:'{import_state.wrapping_algo}'"
            )

        key_material = import_state.key.crypto_key.key.decrypt(
            encrypted_key_material, decrypt_padding
        )
        key_to_import_material_to.crypto_key.key_material = key_material
        LOG.info("Key material: %s", key_material)
        return ImportKeyMaterialResponse()

    @handler("CreateAlias", expand=False)
    def create_alias(
        self, context: RequestContext, create_alias_request: CreateAliasRequest
    ) -> None:
        store = self._get_store(context)
        alias_name = create_alias_request["AliasName"]
        if alias_name in store.aliases:
            alias_arn = store.aliases.get(alias_name).metadata["AliasArn"]
            # AWS itself uses AliasArn instead of AliasName in this exception.
            raise AlreadyExistsException(f"An alias with the name {alias_arn} already exists")
        # KeyId can potentially hold one of multiple different types of key identifiers. _get_key finds a key no
        # matter which type of id is used.
        create_alias_request["TargetKeyId"] = _get_key(
            create_alias_request["TargetKeyId"], store
        ).metadata["KeyId"]
        alias = KmsAlias(create_alias_request)
        store.aliases[alias_name] = alias

    @handler("DeleteAlias", expand=False)
    def delete_alias(
        self, context: RequestContext, delete_alias_request: DeleteAliasRequest
    ) -> None:
        store = self._get_store(context)
        alias_name = delete_alias_request["AliasName"]
        if alias_name not in store.aliases:
            alias_arn = kms_alias_arn(
                delete_alias_request["AliasName"], context.account_id, context.region
            )
            # AWS itself uses AliasArn instead of AliasName in this exception.
            raise NotFoundException(f"Alias {alias_arn} is not found")
        store.aliases.pop(alias_name, None)

    @handler("ListAliases")
    def list_aliases(
        self,
        context: RequestContext,
        key_id: KeyIdType = None,
        limit: LimitType = None,
        marker: MarkerType = None,
    ) -> ListAliasesResponse:
        store = self._get_store(context)
        if key_id:
            # KeyId can potentially hold one of multiple different types of key identifiers. _get_key finds a key no
            # matter which type of id is used.
            key_id = _get_key(key_id, store).metadata["KeyId"]

        matching_aliases = []
        for alias in store.aliases.values():
            if key_id and alias.metadata["TargetKeyId"] != key_id:
                continue
            matching_aliases.append(alias.metadata)
        aliases_list = PaginatedList(matching_aliases)
        limit = limit or 100
        page, next_token = aliases_list.get_page(
            lambda alias_metadata: alias_metadata.get("AliasName"),
            next_token=marker,
            page_size=limit,
        )
        kwargs = {"NextMarker": next_token, "Truncated": True} if next_token else {}
        return ListAliasesResponse(Aliases=page, **kwargs)

    @handler("GetKeyRotationStatus", expand=False)
    def get_key_rotation_status(
        self, context: RequestContext, get_key_rotation_status_request: GetKeyRotationStatusRequest
    ) -> GetKeyRotationStatusResponse:
        key = _get_key(get_key_rotation_status_request.get("KeyId"), self._get_store(context))
        return GetKeyRotationStatusResponse(KeyRotationEnabled=key.is_key_rotation_enabled)

    @handler("DisableKeyRotation", expand=False)
    def disable_key_rotation(
        self, context: RequestContext, disable_key_rotation_request: DisableKeyRotationRequest
    ) -> None:
        key = _get_key(disable_key_rotation_request.get("KeyId"), self._get_store(context))
        key.is_key_rotation_enabled = False

    @handler("EnableKeyRotation", expand=False)
    def enable_key_rotation(
        self, context: RequestContext, enable_key_rotation_request: DisableKeyRotationRequest
    ) -> None:
        key = _get_key(enable_key_rotation_request.get("KeyId"), self._get_store(context))
        key.is_key_rotation_enabled = True

    @handler("ListKeyPolicies", expand=False)
    def list_key_policies(
        self, context: RequestContext, list_key_policies_request: ListKeyPoliciesRequest
    ) -> ListKeyPoliciesResponse:
        _get_key(list_key_policies_request.get("KeyId"), self._get_store(context))
        return ListKeyPoliciesResponse(PolicyNames=["default"], Truncated=False)

    @handler("PutKeyPolicy", expand=False)
    def put_key_policy(
        self, context: RequestContext, put_key_policy_request: PutKeyPolicyRequest
    ) -> None:
        key = _get_key(put_key_policy_request.get("KeyId"), self._get_store(context))
        if put_key_policy_request.get("PolicyName") != "default":
            raise UnsupportedOperationException("Only default policy is supported")
        key.policy = put_key_policy_request.get("Policy")

    @handler("GetKeyPolicy", expand=False)
    def get_key_policy(
        self, context: RequestContext, get_key_policy_request: GetKeyPolicyRequest
    ) -> GetKeyPolicyResponse:
        key = _get_key(get_key_policy_request.get("KeyId"), self._get_store(context))
        if get_key_policy_request.get("PolicyName") != "default":
            raise NotFoundException("No such policy exists")
        return GetKeyPolicyResponse(Policy=key.policy)

    @handler("ListResourceTags", expand=False)
    def list_resource_tags(
        self, context: RequestContext, list_resource_tags_request: ListResourceTagsRequest
    ) -> ListResourceTagsResponse:
        key = _get_key(list_resource_tags_request.get("KeyId"), self._get_store(context))
        keys_list = PaginatedList(
            [{"TagKey": tag_key, "TagValue": tag_value} for tag_key, tag_value in key.tags.items()]
        )
        page, next_token = keys_list.get_page(
            lambda tag: tag.get("TagKey"),
            next_token=list_resource_tags_request.get("Marker"),
            page_size=list_resource_tags_request.get("Limit", 50),
        )
        kwargs = {"NextMarker": next_token, "Truncated": True} if next_token else {}
        return ListResourceTagsResponse(Tags=page, **kwargs)

    @handler("TagResource", expand=False)
    def tag_resource(
        self, context: RequestContext, tag_resource_request: TagResourceRequest
    ) -> None:
        key = _get_key(tag_resource_request.get("KeyId"), self._get_store(context))
        key.add_tags(tag_resource_request.get("Tags"))

    @handler("UntagResource", expand=False)
    def untag_resource(
        self, context: RequestContext, untag_resource_request: UntagResourceRequest
    ) -> None:
        key = _get_key(untag_resource_request.get("KeyId"), self._get_store(context))
        if not untag_resource_request.get("TagKeys"):
            return
        for tag_key in untag_resource_request.get("TagKeys"):
            # AWS doesn't seem to mind removal of a non-existent tag, so we do not raise any exception.
            key.tags.pop(tag_key, None)

    def _validate_key_for_encryption_decryption(self, key: KmsKey):
        if key.metadata["KeyUsage"] != "ENCRYPT_DECRYPT":
            raise InvalidKeyUsageException(
                "KeyUsage for encryption / decryption should be ENCRYPT_DECRYPT"
            )

    def _validate_key_for_sign_verify(self, key: KmsKey):
        if key.metadata["KeyUsage"] != "SIGN_VERIFY":
            raise InvalidKeyUsageException(
                "KeyUsage for signing / verification key should be SIGN_VERIFY"
            )

    def _validate_grant_request(self, data: Dict, store: KmsStore):
        if KEY_ID not in data or GRANTEE_PRINCIPAL not in data or OPERATIONS not in data:
            raise ValidationError("Grant ID, key ID and grantee principal must be specified")

        for operation in data[OPERATIONS]:
            if operation not in VALID_OPERATIONS:
                raise ValidationError(
                    f"Value {[OPERATIONS]} at 'operations' failed to satisfy constraint: Member must satisfy"
                    f" constraint: [Member must satisfy enum value set: {VALID_OPERATIONS}]"
                )

        _verify_key_exists(data[KEY_ID], store)


# ---------------
# UTIL FUNCTIONS
# ---------------

# Different AWS services have some internal integrations with KMS. Some create keys, that are used to encrypt/decrypt
# customer's data. Such keys can't be created from outside for security reasons. So AWS services use some internal
# APIs to do that. Functions here are supposed to be used by other LocalStack services to have similar integrations
# with KMS in LocalStack. As such, they are supposed to be proper APIs (as in error and security handling),
# just with more features.


def set_key_managed(key_id: str, account_id: str, region: str) -> None:
    store = kms_stores[account_id][region]
    key = _get_key(key_id, store)
    key.metadata["KeyManager"] = "AWS"
