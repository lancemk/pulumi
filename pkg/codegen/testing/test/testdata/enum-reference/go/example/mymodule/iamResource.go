// Code generated by test DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package mymodule

import (
	"context"
	"reflect"

	iam "github.com/pulumi/pulumi-google-native/sdk/go/google/iam/v1"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type IamResource struct {
	pulumi.ResourceState
}

// NewIamResource registers a new resource with the given unique name, arguments, and options.
func NewIamResource(ctx *pulumi.Context,
	name string, args *IamResourceArgs, opts ...pulumi.ResourceOption) (*IamResource, error) {
	if args == nil {
		args = &IamResourceArgs{}
	}

	var resource IamResource
	err := ctx.RegisterRemoteComponentResource("example:myModule:IamResource", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

type iamResourceArgs struct {
	Config *iam.AuditConfig `pulumi:"config"`
}

// The set of arguments for constructing a IamResource resource.
type IamResourceArgs struct {
	Config iam.AuditConfigPtrInput
}

func (IamResourceArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*iamResourceArgs)(nil)).Elem()
}

type IamResourceInput interface {
	pulumi.Input

	ToIamResourceOutput() IamResourceOutput
	ToIamResourceOutputWithContext(ctx context.Context) IamResourceOutput
}

func (*IamResource) ElementType() reflect.Type {
	return reflect.TypeOf((**IamResource)(nil)).Elem()
}

func (i *IamResource) ToIamResourceOutput() IamResourceOutput {
	return i.ToIamResourceOutputWithContext(context.Background())
}

func (i *IamResource) ToIamResourceOutputWithContext(ctx context.Context) IamResourceOutput {
	return pulumi.ToOutputWithContext(ctx, i).(IamResourceOutput)
}

type IamResourceOutput struct{ *pulumi.OutputState }

func (IamResourceOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**IamResource)(nil)).Elem()
}

func (o IamResourceOutput) ToIamResourceOutput() IamResourceOutput {
	return o
}

func (o IamResourceOutput) ToIamResourceOutputWithContext(ctx context.Context) IamResourceOutput {
	return o
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*IamResourceInput)(nil)).Elem(), &IamResource{})
	pulumi.RegisterOutputType(IamResourceOutput{})
}