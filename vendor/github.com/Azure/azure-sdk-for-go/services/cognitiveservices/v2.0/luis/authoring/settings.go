package authoring

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
	"github.com/Azure/go-autorest/autorest/validation"
	"github.com/Azure/go-autorest/tracing"
	"github.com/satori/go.uuid"
	"net/http"
)

// SettingsClient is the client for the Settings methods of the Authoring service.
type SettingsClient struct {
	BaseClient
}

// NewSettingsClient creates an instance of the SettingsClient client.
func NewSettingsClient(endpoint string) SettingsClient {
	return SettingsClient{New(endpoint)}
}

// List gets the settings in a version of the application.
// Parameters:
// appID - the application ID.
// versionID - the version ID.
func (client SettingsClient) List(ctx context.Context, appID uuid.UUID, versionID string) (result ListAppVersionSettingObject, err error) {
	if tracing.IsEnabled() {
		ctx = tracing.StartSpan(ctx, fqdn+"/SettingsClient.List")
		defer func() {
			sc := -1
			if result.Response.Response != nil {
				sc = result.Response.Response.StatusCode
			}
			tracing.EndSpan(ctx, sc, err)
		}()
	}
	req, err := client.ListPreparer(ctx, appID, versionID)
	if err != nil {
		err = autorest.NewErrorWithError(err, "authoring.SettingsClient", "List", nil, "Failure preparing request")
		return
	}

	resp, err := client.ListSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		err = autorest.NewErrorWithError(err, "authoring.SettingsClient", "List", resp, "Failure sending request")
		return
	}

	result, err = client.ListResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "authoring.SettingsClient", "List", resp, "Failure responding to request")
	}

	return
}

// ListPreparer prepares the List request.
func (client SettingsClient) ListPreparer(ctx context.Context, appID uuid.UUID, versionID string) (*http.Request, error) {
	urlParameters := map[string]interface{}{
		"Endpoint": client.Endpoint,
	}

	pathParameters := map[string]interface{}{
		"appId":     autorest.Encode("path", appID),
		"versionId": autorest.Encode("path", versionID),
	}

	preparer := autorest.CreatePreparer(
		autorest.AsGet(),
		autorest.WithCustomBaseURL("{Endpoint}/luis/api/v2.0", urlParameters),
		autorest.WithPathParameters("/apps/{appId}/versions/{versionId}/settings", pathParameters))
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

// ListSender sends the List request. The method will close the
// http.Response Body if it receives an error.
func (client SettingsClient) ListSender(req *http.Request) (*http.Response, error) {
	return autorest.SendWithSender(client, req,
		autorest.DoRetryForStatusCodes(client.RetryAttempts, client.RetryDuration, autorest.StatusCodesForRetry...))
}

// ListResponder handles the response to the List request. The method always
// closes the http.Response Body.
func (client SettingsClient) ListResponder(resp *http.Response) (result ListAppVersionSettingObject, err error) {
	err = autorest.Respond(
		resp,
		client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusOK),
		autorest.ByUnmarshallingJSON(&result.Value),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}

// Update updates the settings in a version of the application.
// Parameters:
// appID - the application ID.
// versionID - the version ID.
// listOfAppVersionSettingObject - a list of the updated application version settings.
func (client SettingsClient) Update(ctx context.Context, appID uuid.UUID, versionID string, listOfAppVersionSettingObject []AppVersionSettingObject) (result OperationStatus, err error) {
	if tracing.IsEnabled() {
		ctx = tracing.StartSpan(ctx, fqdn+"/SettingsClient.Update")
		defer func() {
			sc := -1
			if result.Response.Response != nil {
				sc = result.Response.Response.StatusCode
			}
			tracing.EndSpan(ctx, sc, err)
		}()
	}
	if err := validation.Validate([]validation.Validation{
		{TargetValue: listOfAppVersionSettingObject,
			Constraints: []validation.Constraint{{Target: "listOfAppVersionSettingObject", Name: validation.Null, Rule: true, Chain: nil}}}}); err != nil {
		return result, validation.NewError("authoring.SettingsClient", "Update", err.Error())
	}

	req, err := client.UpdatePreparer(ctx, appID, versionID, listOfAppVersionSettingObject)
	if err != nil {
		err = autorest.NewErrorWithError(err, "authoring.SettingsClient", "Update", nil, "Failure preparing request")
		return
	}

	resp, err := client.UpdateSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		err = autorest.NewErrorWithError(err, "authoring.SettingsClient", "Update", resp, "Failure sending request")
		return
	}

	result, err = client.UpdateResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "authoring.SettingsClient", "Update", resp, "Failure responding to request")
	}

	return
}

// UpdatePreparer prepares the Update request.
func (client SettingsClient) UpdatePreparer(ctx context.Context, appID uuid.UUID, versionID string, listOfAppVersionSettingObject []AppVersionSettingObject) (*http.Request, error) {
	urlParameters := map[string]interface{}{
		"Endpoint": client.Endpoint,
	}

	pathParameters := map[string]interface{}{
		"appId":     autorest.Encode("path", appID),
		"versionId": autorest.Encode("path", versionID),
	}

	preparer := autorest.CreatePreparer(
		autorest.AsContentType("application/json; charset=utf-8"),
		autorest.AsPut(),
		autorest.WithCustomBaseURL("{Endpoint}/luis/api/v2.0", urlParameters),
		autorest.WithPathParameters("/apps/{appId}/versions/{versionId}/settings", pathParameters),
		autorest.WithJSON(listOfAppVersionSettingObject))
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

// UpdateSender sends the Update request. The method will close the
// http.Response Body if it receives an error.
func (client SettingsClient) UpdateSender(req *http.Request) (*http.Response, error) {
	return autorest.SendWithSender(client, req,
		autorest.DoRetryForStatusCodes(client.RetryAttempts, client.RetryDuration, autorest.StatusCodesForRetry...))
}

// UpdateResponder handles the response to the Update request. The method always
// closes the http.Response Body.
func (client SettingsClient) UpdateResponder(resp *http.Response) (result OperationStatus, err error) {
	err = autorest.Respond(
		resp,
		client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusOK),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}
