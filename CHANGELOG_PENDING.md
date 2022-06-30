### Improvements

- [plugins] Plugin download urls now support GitHub as a first class url schema. For example "github://api.github.com/pulumiverse".
  [#9984](https://github.com/pulumi/pulumi/pull/9984)

- [backends] When logging in to a file backend, validate that the bucket is accessible.
  [#10012](https://github.com/pulumi/pulumi/pull/10012)

### Bug Fixes

- [cli] `pulumi convert` supports provider packages without a version.
  [#9976](https://github.com/pulumi/pulumi/pull/9976)
