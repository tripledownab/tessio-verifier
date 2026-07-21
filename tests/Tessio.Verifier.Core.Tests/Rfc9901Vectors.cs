namespace Tessio.Verifier.Core.Tests;

/// <summary>
/// Official conformance vectors from RFC 9901 Appendix A.3 (SD-JWT VC example: a German PID,
/// vct urn:eudi:pid:de:1) and A.5 (the issuer key published for validating the examples).
/// These strings are copied verbatim from the RFC and must never be regenerated.
/// </summary>
internal static class Rfc9901Vectors
{
    public const string Issuer = "https://pid-issuer.bund.de.example";

    public const string ExpectedNonce = "1234567890";

    public const string ExpectedAudience = "https://verifier.example.org";

    /// <summary>RFC 9901 A.5 — issuer public key for the examples.</summary>
    public const string IssuerJwk = """{"kty":"EC","crv":"P-256","x":"b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ","y":"Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8"}""";

    /// <summary>A.3 presentation: 3 disclosures (recursive age_equal_or_over) + KB-JWT.</summary>
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

    /// <summary>A.3 issuance: all 28 disclosures, no KB-JWT (ends with a tilde).</summary>
    public const string Issuance =
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
        "bV8xjctX1AlEa5TkdnkKOyWvLfW40XDb5oj9tzkgwff5s44IDnrfAdgLtmTcojs97_Q~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3" +
        "IiwgImdpdmVuX25hbWUiLCAiRXJpa2EiXQ~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIk11c3Rlc" +
        "m1hbm4iXQ~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImJpcnRoZGF0ZSIsICIxOTYzLTA4LTEyIl0~WyJlSThaV205UW5LUH" +
        "BOUGVOZW5IZGhRIiwgInN0cmVldF9hZGRyZXNzIiwgIkhlaWRlc3RyYVx1MDBkZmUgMTciXQ~WyJRZ19PNjR6cUF4ZTQxMmExMDh" +
        "pcm9BIiwgImxvY2FsaXR5IiwgIktcdTAwZjZsbiJd~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgInBvc3RhbF9jb2RlIiwgIj" +
        "UxMTQ3Il0~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImNvdW50cnkiLCAiREUiXQ~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWp" +
        "BIiwgImFkZHJlc3MiLCB7Il9zZCI6IFsiQUxaRVJzU241V05pRVhkQ2tzVzhJNXFRdzNfTnBBblJxcFNBWkR1ZGd3OCIsICJEX19" +
        "XX3VZY3ZSejN0dlVuSUp2QkRIaVRjN0NfX3FIZDB4Tkt3SXNfdzlrIiwgImVCcENYVTFKNWRoSDJnNHQ4UVlOVzVFeFM5QXhVVmJ" +
        "sVW9kb0xZb1BobzAiLCAieE9QeTktZ0pBTEs2VWJXS0ZMUjg1Y09CeVVEM0FiTndGZzNJM1lmUUVfSSJdfV0~WyJsa2x4RjVqTVl" +
        "sR1RQVW92TU5JdkNBIiwgIm5hdGlvbmFsaXRpZXMiLCBbIkRFIl1d~WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgInNleCIsID" +
        "Jd~WyI1YlBzMUlxdVpOYTBoa2FGenp6Wk53IiwgImJpcnRoX2ZhbWlseV9uYW1lIiwgIkdhYmxlciJd~WyI1YTJXMF9OcmxFWnpm" +
        "cW1rXzdQcS13IiwgImxvY2FsaXR5IiwgIkJlcmxpbiJd~WyJ5MXNWVTV3ZGZKYWhWZGd3UGdTN1JRIiwgImNvdW50cnkiLCAiREU" +
        "iXQ~WyJIYlE0WDhzclZXM1FEeG5JSmRxeU9BIiwgInBsYWNlX29mX2JpcnRoIiwgeyJfc2QiOiBbIktVVmlhYUxuWTVqU01MOTBH" +
        "MjlPT0xFTlBiYlhmaFNqU1BNalphR2t4QUUiLCAiWWJzVDBTNzZWcVhDVnNkMWpVU2x3S1BEZ21BTGVCMXVaY2xGSFhmLVVTUSJd" +
        "fV0~WyJDOUdTb3VqdmlKcXVFZ1lmb2pDYjFBIiwgIjEyIiwgdHJ1ZV0~WyJreDVrRjE3Vi14MEptd1V4OXZndnR3IiwgIjE0Iiwg" +
        "dHJ1ZV0~WyJIM28xdXN3UDc2MEZpMnllR2RWQ0VRIiwgIjE2IiwgdHJ1ZV0~WyJPQktsVFZsdkxnLUFkd3FZR2JQOFpBIiwgIjE4" +
        "IiwgdHJ1ZV0~WyJNMEpiNTd0NDF1YnJrU3V5ckRUM3hBIiwgIjIxIiwgdHJ1ZV0~WyJEc210S05ncFY0ZEFIcGpyY2Fvc0F3Iiwg" +
        "IjY1IiwgZmFsc2Vd~WyJlSzVvNXBIZmd1cFBwbHRqMXFoQUp3IiwgImFnZV9lcXVhbF9vcl9vdmVyIiwgeyJfc2QiOiBbIjF0RWl" +
        "5elBSWU9Lc2Y3U3NZR01nUFpLc09UMWxRWlJ4SFhBMHI1X0J3a2siLCAiQ1ZLbmx5NVA5MHlKczNFd3R4UWlPdFVjemFYQ1lOQTR" +
        "JY3pSYW9ock1EZyIsICJhNDQtZzJHcjhfM0FtSncyWFo4a0kxeTBRel96ZTlpT2NXMlczUkxwWEdnIiwgImdrdnkwRnV2QkJ2ajB" +
        "oczJaTnd4Y3FPbGY4bXUyLWtDRTctTmIyUXh1QlUiLCAiaHJZNEhubUY1YjVKd0M5ZVR6YUZDVWNlSVFBYUlkaHJxVVhRTkNXYmZ" +
        "aSSIsICJ5NlNGclZGUnlxNTBJYlJKdmlUWnFxalFXejB0TGl1Q21NZU8wS3FhekdJIl19XQ~WyJqN0FEZGIwVVZiMExpMGNpUGNQ" +
        "MGV3IiwgImFnZV9pbl95ZWFycyIsIDYyXQ~WyJXcHhKckZ1WDh1U2kycDRodDA5anZ3IiwgImFnZV9iaXJ0aF95ZWFyIiwgMTk2M" +
        "10~WyJhdFNtRkFDWU1iSlZLRDA1bzNKZ3RRIiwgImlzc3VhbmNlX2RhdGUiLCAiMjAyMC0wMy0xMSJd~WyI0S3lSMzJvSVp0LXpr" +
        "V3ZGcWJVTEtnIiwgImV4cGlyeV9kYXRlIiwgIjIwMzAtMDMtMTIiXQ~WyJjaEJDc3loeWgtSjg2SS1hd1FEaUNRIiwgImlzc3Vpb" +
        "mdfYXV0aG9yaXR5IiwgIkRFIl0~WyJmbE5QMW5jTXo5TGctYzlxTUl6XzlnIiwgImlzc3VpbmdfY291bnRyeSIsICJERSJd~";
}
