package aws

import (
	"context"
	"net/netip"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type mockEC2Client struct {
	mock.Mock
}

func (client *mockEC2Client) DescribeManagedPrefixLists(ctx context.Context, input *ec2.DescribeManagedPrefixListsInput, fn ...func(*ec2.Options)) (*ec2.DescribeManagedPrefixListsOutput, error) {
	args := client.Called(ctx, input, fn)

	if output := args.Get(0); output != nil {
		return output.(*ec2.DescribeManagedPrefixListsOutput), args.Error(1)
	}

	return nil, args.Error(1)
}

func (client *mockEC2Client) GetManagedPrefixListEntries(ctx context.Context, input *ec2.GetManagedPrefixListEntriesInput, fn ...func(*ec2.Options)) (*ec2.GetManagedPrefixListEntriesOutput, error) {
	args := client.Called(ctx, input, fn)

	if output := args.Get(0); output != nil {
		return output.(*ec2.GetManagedPrefixListEntriesOutput), args.Error(1)
	}

	return nil, args.Error(1)
}

func TestGetManagedPrefixListIpsFromFilter(t *testing.T) {
	t.Parallel()

	tables := []struct {
		name   string
		client func() ec2ManagedPrefixListAPIClient
		filter *api.AWSGroup
		addrs  []netip.Prefix
		err    error
	}{
		{
			name: "example",
			client: func() ec2ManagedPrefixListAPIClient {
				client := new(mockEC2Client)

				client.On("DescribeManagedPrefixLists", mock.Anything, &ec2.DescribeManagedPrefixListsInput{
					Filters: []ec2types.Filter{
						{
							Name: policyManagedPrefixListID,
							Values: []string{
								"pl-1234",
							},
						},
					},
				}, mock.Anything).Return(&ec2.DescribeManagedPrefixListsOutput{
					PrefixLists: []ec2types.ManagedPrefixList{
						{
							PrefixListId: aws.String("pl-1234"),
						},
					},
				}, nil).Once()

				client.On("GetManagedPrefixListEntries", mock.Anything, &ec2.GetManagedPrefixListEntriesInput{
					PrefixListId: aws.String("pl-1234"),
				}, mock.Anything).Return(&ec2.GetManagedPrefixListEntriesOutput{
					Entries: []ec2types.PrefixListEntry{
						{
							Cidr: aws.String("5.6.7.8/32"),
						},
						{
							Cidr: aws.String("1.2.3.4/32"),
						},
					},
				}, nil).Once()

				return client
			},
			filter: &api.AWSGroup{
				ManagedPrefixListsIds: []string{
					"pl-1234",
				},
			},
			addrs: []netip.Prefix{
				netip.MustParsePrefix("5.6.7.8/32"),
				netip.MustParsePrefix("1.2.3.4/32"),
			},
		},
	}

	for _, table := range tables {
		t.Run(table.name, func(t *testing.T) {
			t.Parallel()

			addrs, err := getManagedPrefixListIpsFromFilter(t.Context(), table.filter, table.client())
			if table.err == nil {
				require.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, table.err)

				return
			}

			assert.Equal(t, table.addrs, addrs)
		})
	}
}
