package subscriptionapi

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
	"github.com/Azure/azure-sdk-for-go/services/preview/subscription/mgmt/2018-03-01-preview/subscription"
)

// OperationsClientAPI contains the set of methods on the OperationsClient type.
type OperationsClientAPI interface {
	List(ctx context.Context) (result subscription.OperationListResult, err error)
}

var _ OperationsClientAPI = (*subscription.OperationsClient)(nil)

// OperationsGroupClientAPI contains the set of methods on the OperationsGroupClient type.
type OperationsGroupClientAPI interface {
	List(ctx context.Context) (result subscription.OperationListResultType, err error)
}

var _ OperationsGroupClientAPI = (*subscription.OperationsGroupClient)(nil)

// FactoryClientAPI contains the set of methods on the FactoryClient type.
type FactoryClientAPI interface {
	CreateSubscriptionInEnrollmentAccount(ctx context.Context, enrollmentAccountName string, body subscription.CreationParameters) (result subscription.FactoryCreateSubscriptionInEnrollmentAccountFuture, err error)
}

var _ FactoryClientAPI = (*subscription.FactoryClient)(nil)

// SubscriptionsClientAPI contains the set of methods on the SubscriptionsClient type.
type SubscriptionsClientAPI interface {
	Get(ctx context.Context, subscriptionID string) (result subscription.Model, err error)
	List(ctx context.Context) (result subscription.ListResultPage, err error)
	ListLocations(ctx context.Context, subscriptionID string) (result subscription.LocationListResult, err error)
}

var _ SubscriptionsClientAPI = (*subscription.SubscriptionsClient)(nil)

// TenantsClientAPI contains the set of methods on the TenantsClient type.
type TenantsClientAPI interface {
	List(ctx context.Context) (result subscription.TenantListResultPage, err error)
}

var _ TenantsClientAPI = (*subscription.TenantsClient)(nil)
