namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// The pinned conformance fixture TEST mode replays: RFC 9901 Appendix A.3, the specification's own
/// SD-JWT VC example (a German PID, vct urn:eudi:pid:de:1), with the issuer key the RFC publishes in
/// Appendix A.5. Copied verbatim from the RFC; never regenerate.
/// </summary>
internal static class ConformanceFixture
{
    public const string Name = "rfc9901-a3-pid";

    public const string Issuer = "https://pid-issuer.bund.de.example";

    public const string Vct = "urn:eudi:pid:de:1";

    /// <summary>The nonce and audience baked into the example's KB-JWT.</summary>
    public const string Nonce = "1234567890";

    public const string Audience = "https://verifier.example.org";

    public const string IssuerMetadataUrl = "https://pid-issuer.bund.de.example/.well-known/jwt-vc-issuer";

    public const string IssuerMetadataJson =
        """{"issuer":"https://pid-issuer.bund.de.example","jwks":{"keys":[{"kty":"EC","crv":"P-256","x":"b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ","y":"Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8"}]}}""";

    public const string Presentation =
        "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImRjK3NkLWp3dCJ9.eyJfc2QiOiBbIjBIWm1uU0lQejMzN2tTV2U3QzM0bC0tODhnekp" +
        "pLWVCSjJWel9ISndBVGciLCAiMUNybjAzV21VZVJXcDR6d1B2dkNLWGw5WmFRcC1jZFFWX2dIZGFHU1dvdyIsICIycjAwOWR6dkh" +
        "1VnJXclJYVDVrSk1tSG5xRUhIbldlME1MVlp3OFBBVEI4IiwgIjZaTklTRHN0NjJ5bWxyT0FrYWRqZEQ1WnVsVDVBMjk5Sjc4U0x" +
        "oTV9fT3MiLCAiNzhqZzc3LUdZQmVYOElRZm9FTFB5TDBEWVBkbWZabzBKZ1ZpVjBfbEtDTSIsICI5MENUOEFhQlBibjVYOG5SWGt" +
        "lc2p1MWkwQnFoV3FaM3dxRDRqRi1xREdrIiwgIkkwMGZjRlVvRFhDdWNwNXl5MnVqcVBzc0RWR2FXTmlVbGlOel9hd0QwZ2MiLCA" +
        "iS2pBWGdBQTlONVdIRUR0UkloNHU1TW4xWnNXaXhoaFdBaVgtQTRRaXdnQSIsICJMYWk2SVU2ZDdHUWFnWFI3QXZHVHJuWGdTbGQ" +
        "zejhFSWdfZnYzZk9aMVdnIiwgIkxlemphYlJxaVpPWHpFWW1WWmY4Uk1pOXhBa2QzX00xTFo4VTdFNHMzdTQiLCAiUlR6M3FUbUZ" +
        "OSGJwV3JyT01aUzQxRjQ3NGtGcVJ2M3ZJUHF0aDZQVWhsTSIsICJXMTRYSGJVZmZ6dVc0SUZNanBTVGIxbWVsV3hVV2Y0Tl9vMmx" +
        "ka2tJcWM4IiwgIldUcEk3UmNNM2d4WnJ1UnBYemV6U2JrYk9yOTNQVkZ2V3g4d29KM2oxY0UiLCAiX29oSlZJUUlCc1U0dXBkTlM" +
        "0X3c0S2IxTUhxSjBMOXFMR3NoV3E2SlhRcyIsICJ5NTBjemMwSVNDaHlfYnNiYTFkTW9VdUFPUTVBTW1PU2ZHb0VlODF2MUZVIl0" +
        "sICJpc3MiOiAiaHR0cHM6Ly9waWQtaXNzdWVyLmJ1bmQuZGUuZXhhbXBsZSIsICJpYXQiOiAxNjgzMDAwMDAwLCAiZXhwIjogMTg" +
        "4MzAwMDAwMCwgInZjdCI6ICJ1cm46ZXVkaTpwaWQ6ZGU6MSIsICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB" +
        "7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2V" +
        "HZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0.ZOZQTqmq8X1mCyFXi0w" +
        "bV8xjctX1AlEa5TkdnkKOyWvLfW40XDb5oj9tzkgwff5s44IDnrfAdgLtmTcojs97_Q~WyJlSzVvNXBIZmd1cFBwbHRqMXFoQUp3" +
        "IiwgImFnZV9lcXVhbF9vcl9vdmVyIiwgeyJfc2QiOiBbIjF0RWl5elBSWU9Lc2Y3U3NZR01nUFpLc09UMWxRWlJ4SFhBMHI1X0J3" +
        "a2siLCAiQ1ZLbmx5NVA5MHlKczNFd3R4UWlPdFVjemFYQ1lOQTRJY3pSYW9ock1EZyIsICJhNDQtZzJHcjhfM0FtSncyWFo4a0kx" +
        "eTBRel96ZTlpT2NXMlczUkxwWEdnIiwgImdrdnkwRnV2QkJ2ajBoczJaTnd4Y3FPbGY4bXUyLWtDRTctTmIyUXh1QlUiLCAiaHJZ" +
        "NEhubUY1YjVKd0M5ZVR6YUZDVWNlSVFBYUlkaHJxVVhRTkNXYmZaSSIsICJ5NlNGclZGUnlxNTBJYlJKdmlUWnFxalFXejB0TGl1" +
        "Q21NZU8wS3FhekdJIl19XQ~WyJPQktsVFZsdkxnLUFkd3FZR2JQOFpBIiwgIjE4IiwgdHJ1ZV0~WyJsa2x4RjVqTVlsR1RQVW92T" +
        "U5JdkNBIiwgIm5hdGlvbmFsaXRpZXMiLCBbIkRFIl1d~eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9.eyJub25jZSI" +
        "6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUub3JnIiwgImlhdCI6IDE3NDg1MzcyNDQsICJ" +
        "zZF9oYXNoIjogIlBqTVlmTTA3VmJKZE14TElsdXZSTmI4OEpGbGpTWDRuLUc0M1VjX0JTUk0ifQ.f3TeS_1BWEG78EbIJRh5wgv8" +
        "nYumk7euzu6xgbgpNB4pbQQqgRPWK-vQjlhhgU1EFGZ9LFakFX_0mgul1G_3mw";
}
