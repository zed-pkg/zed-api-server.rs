import "@typespec/json-schema";
using TypeSpec.JsonSchema;

namespace Zed.Api;

@id("ZedApiToolchainContract")
model ZedApiToolchainContract {
  schema: "zed.api/toolchain-contract/v1";
  @pattern("^[0-9a-f]{40}$")
  flags2envRevision: string;
  cargoPackageName: "zed-api-server";
  cargoPackageVersion: string;
  zedPackageName: "zed-api-server";
  zedPackageVersion: string;
  packageRepositoryMatch: true;
  cargoLockMatchesPackage: true;
  canonicalFlagsAuthority: true;
  strictUnknownOptions: true;
  dotenvDisabled: true;
  flagCount: 36;
  requiredSecretEnvIgnored: true;
  legacyFlagsAuthorityPresent: false;
}
