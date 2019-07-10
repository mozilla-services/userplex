// Code generated by private/model/cli/gen-api/main.go. DO NOT EDIT.

package licensemanager

const (

	// ErrCodeAccessDeniedException for service response error code
	// "AccessDeniedException".
	//
	// Access to resource denied.
	ErrCodeAccessDeniedException = "AccessDeniedException"

	// ErrCodeAuthorizationException for service response error code
	// "AuthorizationException".
	//
	// The AWS user account does not have permission to perform the action. Check
	// the IAM policy associated with this account.
	ErrCodeAuthorizationException = "AuthorizationException"

	// ErrCodeFailedDependencyException for service response error code
	// "FailedDependencyException".
	//
	// A dependency required to run the API is missing.
	ErrCodeFailedDependencyException = "FailedDependencyException"

	// ErrCodeFilterLimitExceededException for service response error code
	// "FilterLimitExceededException".
	//
	// The request uses too many filters or too many filter values.
	ErrCodeFilterLimitExceededException = "FilterLimitExceededException"

	// ErrCodeInvalidParameterValueException for service response error code
	// "InvalidParameterValueException".
	//
	// One or more parameter values are not valid.
	ErrCodeInvalidParameterValueException = "InvalidParameterValueException"

	// ErrCodeInvalidResourceStateException for service response error code
	// "InvalidResourceStateException".
	//
	// License Manager cannot allocate a license to a resource because of its state.
	//
	// For example, you cannot allocate a license to an instance in the process
	// of shutting down.
	ErrCodeInvalidResourceStateException = "InvalidResourceStateException"

	// ErrCodeLicenseUsageException for service response error code
	// "LicenseUsageException".
	//
	// You do not have enough licenses available to support a new resource launch.
	ErrCodeLicenseUsageException = "LicenseUsageException"

	// ErrCodeRateLimitExceededException for service response error code
	// "RateLimitExceededException".
	//
	// Too many requests have been submitted. Try again after a brief wait.
	ErrCodeRateLimitExceededException = "RateLimitExceededException"

	// ErrCodeResourceLimitExceededException for service response error code
	// "ResourceLimitExceededException".
	//
	// Your resource limits have been exceeded.
	ErrCodeResourceLimitExceededException = "ResourceLimitExceededException"

	// ErrCodeServerInternalException for service response error code
	// "ServerInternalException".
	//
	// The server experienced an internal error. Try again.
	ErrCodeServerInternalException = "ServerInternalException"
)
