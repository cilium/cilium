package proto

import (
	"fmt"
)

var (
	ErrUnknown                                 = &KafkaError{-1, "unknown error"}
	ErrOffsetOutOfRange                        = &KafkaError{1, "offset out of range"}
	ErrInvalidMessage                          = &KafkaError{2, "invalid message"}
	ErrUnknownTopicOrPartition                 = &KafkaError{3, "unknown topic or partition"}
	ErrInvalidMessageSize                      = &KafkaError{4, "invalid message size"}
	ErrLeaderNotAvailable                      = &KafkaError{5, "leader not available"}
	ErrNotLeaderForPartition                   = &KafkaError{6, "not leader for partition"}
	ErrRequestTimeout                          = &KafkaError{7, "request timeed out"}
	ErrBrokerNotAvailable                      = &KafkaError{8, "broker not available"}
	ErrReplicaNotAvailable                     = &KafkaError{9, "replica not available"}
	ErrMessageSizeTooLarge                     = &KafkaError{10, "message size too large"}
	ErrScaleControllerEpoch                    = &KafkaError{11, "scale controller epoch"}
	ErrOffsetMetadataTooLarge                  = &KafkaError{12, "offset metadata too large"}
	ErrNetwork                                 = &KafkaError{13, "server disconnected before response was received"}
	ErrOffsetLoadInProgress                    = &KafkaError{14, "offsets load in progress"}
	ErrNoCoordinator                           = &KafkaError{15, "consumer coordinator not available"}
	ErrNotCoordinator                          = &KafkaError{16, "not coordinator for consumer"}
	ErrInvalidTopic                            = &KafkaError{17, "operation on an invalid topic"}
	ErrRecordListTooLarge                      = &KafkaError{18, "message batch larger than the configured segment size"}
	ErrNotEnoughReplicas                       = &KafkaError{19, "not enough in-sync replicas"}
	ErrNotEnoughReplicasAfterAppend            = &KafkaError{20, "messages are written to the log, but to fewer in-sync replicas than required"}
	ErrInvalidRequiredAcks                     = &KafkaError{21, "invalid value for required acks"}
	ErrIllegalGeneration                       = &KafkaError{22, "consumer generation id is not valid"}
	ErrInconsistentPartitionAssignmentStrategy = &KafkaError{23, "partition assignment strategy does not match that of the group"}
	ErrUnknownParititonAssignmentStrategy      = &KafkaError{24, "partition assignment strategy is unknown to the broker"}
	ErrUnknownConsumerID                       = &KafkaError{25, "coordinator is not aware of this consumer"}
	ErrInvalidSessionTimeout                   = &KafkaError{26, "invalid session timeout"}
	ErrRebalanceInProgress                     = &KafkaError{27, "group is rebalancing, so a rejoin is needed"}
	ErrInvalidCommitOffsetSize                 = &KafkaError{28, "offset data size is not valid"}
	ErrTopicAuthorizationFailed                = &KafkaError{29, "topic authorization failed"}
	ErrGroupAuthorizationFailed                = &KafkaError{30, "group authorization failed"}
	ErrClusterAuthorizationFailed              = &KafkaError{31, "cluster authorization failed"}
	ErrInvalidTimeStamp                        = &KafkaError{32, "timestamp of the message is out of acceptable range"}
	ErrUnsupportedSaslMechanism                = &KafkaError{33, "The broker does not support the requested SASL mechanism."}
	ErrIllegalSaslState                        = &KafkaError{34, "Request is not valid given the current SASL state."}
	ErrUnsupportedVersion                      = &KafkaError{35, "The version of API is not supported."}
	ErrTopicAlreadyExists                      = &KafkaError{36, "Topic with this name already exists."}
	ErrInvalidPartitions                       = &KafkaError{37, "Number of partitions is invalid."}
	ErrInvalidReplicationFactor                = &KafkaError{38, "Replication-factor is invalid."}
	ErrInvalidReplicaAssignment                = &KafkaError{39, "Replica assignment is invalid."}
	ErrInvalidConfig                           = &KafkaError{40, "Configuration is invalid."}
	ErrNotController                           = &KafkaError{41, "This is not the correct controller for this cluster."}
	ErrInvalidRequest                          = &KafkaError{42, "This most likely occurs because of a request being malformed by the client library or the message was sent to an incompatible broker. See the broker logs for more details."}
	ErrUnsupportedForMessageFormat             = &KafkaError{43, "The message format version on the broker does not support the request."}
	ErrPolicyViolation                         = &KafkaError{44, "Request parameters do not satisfy the configured policy."}
	ErrOutOfOrderSequenceNumber                = &KafkaError{45, "The broker received an out of order sequence number"}
	ErrDuplicateSequenceNumber                 = &KafkaError{46, "The broker received a duplicate sequence number"}
	ErrInvalidProducerEpoch                    = &KafkaError{47, "Producer attempted an operation with an old epoch. Either there is a newer producer with the same transactionalId, or the producer's transaction has been expired by the broker."}
	ErrInvalidTxnState                         = &KafkaError{48, "The producer attempted a transactional operation in an invalid state"}
	ErrInvalidProducerIdMapping                = &KafkaError{49, "The producer attempted to use a producer id which is not currently assigned to its transactional id"}
	ErrInvalidTransactionTimeout               = &KafkaError{50, "The transaction timeout is larger than the maximum value allowed by the broker (as configured by transaction.max.timeout.ms)."}
	ErrConcurrentTransactions                  = &KafkaError{51, "The producer attempted to update a transaction while another concurrent operation on the same transaction was ongoing"}
	ErrTransactionCoordinatorFenced            = &KafkaError{52, "Indicates that the transaction coordinator sending a WriteTxnMarker is no longer the current coordinator for a given producer"}
	ErrTransactionalIdAuthorizationFailed      = &KafkaError{53, "Transactional Id authorization failed"}
	ErrSecurityDisabled                        = &KafkaError{54, "Security features are disabled."}
	ErrOperationNotAttempted                   = &KafkaError{55, "The broker did not attempt to execute this operation. This may happen for batched RPCs where some operations in the batch failed, causing the broker to respond without trying the rest."}
	ErrKafkaStorageError                       = &KafkaError{56, "Disk error when trying to access log file on the disk."}
	ErrLogDirNotFound                          = &KafkaError{57, "The user-specified log directory is not found in the broker config."}
	ErrSaslAuthenticationFailed                = &KafkaError{58, "SASL Authentication failed."}
	ErrUnknownProducerId                       = &KafkaError{59, "This exception is raised by the broker if it could not locate the producer metadata associated with the producerId in question. This could happen if, for instance, the producer's records were deleted because their retention time had elapsed. Once the last records of the producerId are removed, the producer's metadata is removed from the broker, and future appends by the producer will return this exception."}
	ErrReassignmentInProgress                  = &KafkaError{60, "A partition reassignment is in progress"}
	ErrDelegationTokenAuthDisabled             = &KafkaError{61, "Delegation Token feature is not enabled."}
	ErrDelegationTokenNotFound                 = &KafkaError{62, "Delegation Token is not found on server."}
	ErrDelegationTokenOwnerMismatch            = &KafkaError{63, "Specified Principal is not valid Owner/Renewer."}
	ErrDelegationTokenRequestNotAllowed        = &KafkaError{64, "Delegation Token requests are not allowed on PLAINTEXT/1-way SSL channels and on delegation token authenticated channels."}
	ErrDelegationTokenAuthorizationFailed      = &KafkaError{65, "Delegation Token authorization failed."}
	ErrDelegationTokenExpired                  = &KafkaError{66, "Delegation Token is expired."}
	ErrInvalidPrincipalType                    = &KafkaError{67, "Supplied principalType is not supported"}
	ErrNonEmptyGroup                           = &KafkaError{68, "The group The group is not empty is not empty"}
	ErrGroupIdNotFound                         = &KafkaError{69, "The group id The group id does not exist was not found"}
	ErrFetchSessionIdNotFound                  = &KafkaError{70, "The fetch session ID was not found"}
	ErrInvalidFetchSessionEpoch                = &KafkaError{71, "The fetch session epoch is invalid"}

	errnoToErr = map[int16]error{
		-1: ErrUnknown,
		1:  ErrOffsetOutOfRange,
		2:  ErrInvalidMessage,
		3:  ErrUnknownTopicOrPartition,
		4:  ErrInvalidMessageSize,
		5:  ErrLeaderNotAvailable,
		6:  ErrNotLeaderForPartition,
		7:  ErrRequestTimeout,
		8:  ErrBrokerNotAvailable,
		9:  ErrReplicaNotAvailable,
		10: ErrMessageSizeTooLarge,
		11: ErrScaleControllerEpoch,
		12: ErrOffsetMetadataTooLarge,
		13: ErrNetwork,
		14: ErrOffsetLoadInProgress,
		15: ErrNoCoordinator,
		16: ErrNotCoordinator,
		17: ErrInvalidTopic,
		18: ErrRecordListTooLarge,
		19: ErrNotEnoughReplicas,
		20: ErrNotEnoughReplicasAfterAppend,
		21: ErrInvalidRequiredAcks,
		22: ErrIllegalGeneration,
		23: ErrInconsistentPartitionAssignmentStrategy,
		24: ErrUnknownParititonAssignmentStrategy,
		25: ErrUnknownConsumerID,
		26: ErrInvalidSessionTimeout,
		27: ErrRebalanceInProgress,
		28: ErrInvalidCommitOffsetSize,
		29: ErrTopicAuthorizationFailed,
		30: ErrGroupAuthorizationFailed,
		31: ErrClusterAuthorizationFailed,
		32: ErrInvalidCommitOffsetSize,
		33: ErrUnsupportedSaslMechanism,
		34: ErrIllegalSaslState,
		35: ErrUnsupportedVersion,
		36: ErrTopicAlreadyExists,
		37: ErrInvalidPartitions,
		38: ErrInvalidReplicationFactor,
		39: ErrInvalidReplicaAssignment,
		40: ErrInvalidConfig,
		41: ErrNotController,
		42: ErrInvalidRequest,
		43: ErrUnsupportedForMessageFormat,
		44: ErrPolicyViolation,
		45: ErrOutOfOrderSequenceNumber,
		46: ErrDuplicateSequenceNumber,
		47: ErrInvalidProducerEpoch,
		48: ErrInvalidTxnState,
		49: ErrInvalidProducerIdMapping,
		50: ErrInvalidTransactionTimeout,
		51: ErrConcurrentTransactions,
		52: ErrTransactionCoordinatorFenced,
		53: ErrTransactionalIdAuthorizationFailed,
		54: ErrSecurityDisabled,
		55: ErrOperationNotAttempted,
		56: ErrKafkaStorageError,
		57: ErrLogDirNotFound,
		58: ErrSaslAuthenticationFailed,
		59: ErrUnknownProducerId,
		60: ErrReassignmentInProgress,
		61: ErrDelegationTokenAuthDisabled,
		62: ErrDelegationTokenNotFound,
		63: ErrDelegationTokenOwnerMismatch,
		64: ErrDelegationTokenRequestNotAllowed,
		65: ErrDelegationTokenAuthorizationFailed,
		66: ErrDelegationTokenExpired,
		67: ErrInvalidPrincipalType,
		68: ErrNonEmptyGroup,
		69: ErrGroupIdNotFound,
		70: ErrFetchSessionIdNotFound,
		71: ErrInvalidFetchSessionEpoch,
	}
)

type KafkaError struct {
	errno   int16
	message string
}

func (err *KafkaError) Error() string {
	return fmt.Sprintf("%s (%d)", err.message, err.errno)
}

func (err *KafkaError) Errno() int {
	return int(err.errno)
}

func errFromNo(errno int16) error {
	if errno == 0 {
		return nil
	}
	err, ok := errnoToErr[errno]
	if !ok {
		return fmt.Errorf("unknown kafka error %d", errno)
	}
	return err
}
