/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package azure

import (
	"fmt"

	azs "github.com/Azure/azure-sdk-for-go/storage"
	"github.com/golang/glog"
)

const (
	useHTTPS = true
)

// create file share
func (az *Cloud) createFileShare(accountName, accountKey, name string, sizeGB int) error {
	fileClient, err := az.getFileSvcClient(accountName, accountKey)
	if err != nil {
		return err
	}
	// create a file share and set quota
	// Note. Per https://docs.microsoft.com/en-us/rest/api/storageservices/fileservices/Create-Share,
	// setting x-ms-share-quota can set quota on the new share, but in reality, setting quota in CreateShare
	// receives error "The metadata specified is invalid. It has characters that are not permitted."
	// As a result,breaking into two API calls: create share and set quota
	share := fileClient.GetShareReference(name)
	if err = share.Create(nil); err != nil {
		return fmt.Errorf("failed to create file share, err: %v", err)
	}
	share.Properties.Quota = sizeGB
	if err = share.SetProperties(nil); err != nil {
		if err := share.Delete(nil); err != nil {
			glog.Errorf("Error deleting share: %v", err)
		}
		return fmt.Errorf("failed to set quota on file share %s, err: %v", name, err)
	}
	return nil
}

// delete a file share
func (az *Cloud) deleteFileShare(accountName, accountKey, name string) error {
	fileClient, err := az.getFileSvcClient(accountName, accountKey)
	if err == nil {
		share := fileClient.GetShareReference(name)
		return share.Delete(nil)
	}
	return nil
}

func (az *Cloud) getFileSvcClient(accountName, accountKey string) (*azs.FileServiceClient, error) {
	client, err := azs.NewClient(accountName, accountKey, az.Environment.StorageEndpointSuffix, azs.DefaultAPIVersion, useHTTPS)
	if err != nil {
		return nil, fmt.Errorf("error creating azure client: %v", err)
	}
	f := client.GetFileService()
	return &f, nil
}
