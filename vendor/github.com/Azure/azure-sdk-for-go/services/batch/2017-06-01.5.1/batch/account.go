package batch

// Copyright (c) Microsoft and contributors.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

import (
	"context"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/date"
	"github.com/Azure/go-autorest/autorest/validation"
	"github.com/satori/go.uuid"
	"net/http"
)

// AccountClient is the a client for issuing REST requests to the Azure Batch service.
type AccountClient struct {
	BaseClient
}

// NewAccountClient creates an instance of the AccountClient client.
func NewAccountClient() AccountClient {
	return NewAccountClientWithBaseURI(DefaultBaseURI)
}

// NewAccountClientWithBaseURI creates an instance of the AccountClient client.
func NewAccountClientWithBaseURI(baseURI string) AccountClient {
	return AccountClient{NewWithBaseURI(baseURI)}
}

// ListNodeAgentSkus sends the list node agent skus request.
//
// filter is an OData $filter clause. maxResults is the maximum number of items to return in the response. A
// maximum of 1000 results will be returned. timeout is the maximum time that the server can spend processing the
// request, in seconds. The default is 30 seconds. clientRequestID is the caller-generated request identity, in the
// form of a GUID with no decoration such as curly braces, e.g. 9C4D50EE-2D56-4CD3-8152-34347DC9F2B0.
// returnClientRequestID is whether the server should return the client-request-id in the response. ocpDate is the
// time the request was issued. Client libraries typically set this to the current system clock time; set it
// explicitly if you are calling the REST API directly.
func (client AccountClient) ListNodeAgentSkus(ctx context.Context, filter string, maxResults *int32, timeout *int32, clientRequestID *uuid.UUID, returnClientRequestID *bool, ocpDate *date.TimeRFC1123) (result AccountListNodeAgentSkusResultPage, err error) {
	if err := validation.Validate([]validation.Validation{
		{TargetValue: maxResults,
			Constraints: []validation.Constraint{{Target: "maxResults", Name: validation.Null, Rule: false,
				Chain: []validation.Constraint{{Target: "maxResults", Name: validation.InclusiveMaximum, Rule: 1000, Chain: nil},
					{Target: "maxResults", Name: validation.InclusiveMinimum, Rule: 1, Chain: nil},
				}}}}}); err != nil {
		return result, validation.NewError("batch.AccountClient", "ListNodeAgentSkus", err.Error())
	}

	result.fn = client.listNodeAgentSkusNextResults
	req, err := client.ListNodeAgentSkusPreparer(ctx, filter, maxResults, timeout, clientRequestID, returnClientRequestID, ocpDate)
	if err != nil {
		err = autorest.NewErrorWithError(err, "batch.AccountClient", "ListNodeAgentSkus", nil, "Failure preparing request")
		return
	}

	resp, err := client.ListNodeAgentSkusSender(req)
	if err != nil {
		result.alnasr.Response = autorest.Response{Response: resp}
		err = autorest.NewErrorWithError(err, "batch.AccountClient", "ListNodeAgentSkus", resp, "Failure sending request")
		return
	}

	result.alnasr, err = client.ListNodeAgentSkusResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "batch.AccountClient", "ListNodeAgentSkus", resp, "Failure responding to request")
	}

	return
}

// ListNodeAgentSkusPreparer prepares the ListNodeAgentSkus request.
func (client AccountClient) ListNodeAgentSkusPreparer(ctx context.Context, filter string, maxResults *int32, timeout *int32, clientRequestID *uuid.UUID, returnClientRequestID *bool, ocpDate *date.TimeRFC1123) (*http.Request, error) {
	const APIVersion = "2017-06-01.5.1"
	queryParameters := map[string]interface{}{
		"api-version": APIVersion,
	}
	if len(filter) > 0 {
		queryParameters["$filter"] = autorest.Encode("query", filter)
	}
	if maxResults != nil {
		queryParameters["maxresults"] = autorest.Encode("query", *maxResults)
	} else {
		queryParameters["maxresults"] = autorest.Encode("query", 1000)
	}
	if timeout != nil {
		queryParameters["timeout"] = autorest.Encode("query", *timeout)
	} else {
		queryParameters["timeout"] = autorest.Encode("query", 30)
	}

	preparer := autorest.CreatePreparer(
		autorest.AsGet(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPath("/nodeagentskus"),
		autorest.WithQueryParameters(queryParameters))
	if clientRequestID != nil {
		preparer = autorest.DecoratePreparer(preparer,
			autorest.WithHeader("client-request-id", autorest.String(clientRequestID)))
	}
	if returnClientRequestID != nil {
		preparer = autorest.DecoratePreparer(preparer,
			autorest.WithHeader("return-client-request-id", autorest.String(returnClientRequestID)))
	} else {
		preparer = autorest.DecoratePreparer(preparer,
			autorest.WithHeader("return-client-request-id", autorest.String(false)))
	}
	if ocpDate != nil {
		preparer = autorest.DecoratePreparer(preparer,
			autorest.WithHeader("ocp-date", autorest.String(ocpDate)))
	}
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

// ListNodeAgentSkusSender sends the ListNodeAgentSkus request. The method will close the
// http.Response Body if it receives an error.
func (client AccountClient) ListNodeAgentSkusSender(req *http.Request) (*http.Response, error) {
	return autorest.SendWithSender(client, req,
		autorest.DoRetryForStatusCodes(client.RetryAttempts, client.RetryDuration, autorest.StatusCodesForRetry...))
}

// ListNodeAgentSkusResponder handles the response to the ListNodeAgentSkus request. The method always
// closes the http.Response Body.
func (client AccountClient) ListNodeAgentSkusResponder(resp *http.Response) (result AccountListNodeAgentSkusResult, err error) {
	err = autorest.Respond(
		resp,
		client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusOK),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}

// listNodeAgentSkusNextResults retrieves the next set of results, if any.
func (client AccountClient) listNodeAgentSkusNextResults(lastResults AccountListNodeAgentSkusResult) (result AccountListNodeAgentSkusResult, err error) {
	req, err := lastResults.accountListNodeAgentSkusResultPreparer()
	if err != nil {
		return result, autorest.NewErrorWithError(err, "batch.AccountClient", "listNodeAgentSkusNextResults", nil, "Failure preparing next results request")
	}
	if req == nil {
		return
	}
	resp, err := client.ListNodeAgentSkusSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		return result, autorest.NewErrorWithError(err, "batch.AccountClient", "listNodeAgentSkusNextResults", resp, "Failure sending next results request")
	}
	result, err = client.ListNodeAgentSkusResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "batch.AccountClient", "listNodeAgentSkusNextResults", resp, "Failure responding to next results request")
	}
	return
}

// ListNodeAgentSkusComplete enumerates all values, automatically crossing page boundaries as required.
func (client AccountClient) ListNodeAgentSkusComplete(ctx context.Context, filter string, maxResults *int32, timeout *int32, clientRequestID *uuid.UUID, returnClientRequestID *bool, ocpDate *date.TimeRFC1123) (result AccountListNodeAgentSkusResultIterator, err error) {
	result.page, err = client.ListNodeAgentSkus(ctx, filter, maxResults, timeout, clientRequestID, returnClientRequestID, ocpDate)
	return
}
