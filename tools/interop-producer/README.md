# Interop fixture producer

Generates the cross-implementation fixture pinned in
`tests/Tessio.Verifier.Core.Mdoc.Tests/WalletFrameworkInteropVectors.cs`: our issuer creates an
mdoc, the OpenWallet Foundation wallet-framework-dotnet (an independent implementation) parses it
and builds + COSE-signs the device authentication over an OpenID4VP 1.0 Annex B.2.6.1 session
transcript. Tessio's verifier must accept the result.

Not part of the solution: requires a .NET 10 SDK (WalletFramework 3.x targets net10.0). Run with
`dotnet run` and pin the emitted `fixture.json` only deliberately; the checked-in fixture is a
conformance anchor.

Historical note: generating this fixture against WalletFramework 2.0.0 surfaced a real
nonconformance in that release (SessionTranscript omitted the two required nulls), fixed in 3.x.
