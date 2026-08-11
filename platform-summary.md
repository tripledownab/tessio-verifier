# Tessio.Verifier — Platform Summary

Tessio.Verifier is an open-source **.NET / ASP.NET Core** library for verifying credentials from **EU Digital Identity (EUDI) Wallets**, on the relying-party side. It implements **OpenID4VP 1.0** with **SD-JWT VC** and **mdoc** (ISO 18013-5/-7, the mDL) credentials, and never acts as a wallet or an issuer. Built by **Triple Down AB** and published on NuGet under **Apache-2.0**, it wires into ASP.NET Core through dependency injection and minimal-API endpoints, so it looks like the rest of a .NET team's stack.

It exists because of a hard deadline. Under **Regulation (EU) 2024/1183 (eIDAS 2.0)**, member states must ship a certified EUDI Wallet by **December 2026** and regulated relying parties must accept it by **December 2027**. Existing open-source tooling is Kotlin, Rust and TypeScript, so .NET teams had no native option until now. Four modes let teams build before real wallets exist: **Demo** auto-completes locally, **Mock** runs a built-in wallet through the full pipeline, **Test** replays the RFC 9901 spec vector and **Live** serves real wallets with signed requests and encrypted responses.

For production, a relying party needs a **WRPAC** certificate (ETSI TS 119 475) and must validate the EU trust hierarchy across all 27 member states. The library isolates this behind one **`ITrustListResolver`** seam, and a managed layer supplies registration, WRPAC and live trust lists, with no HSM required on the relying-party side.

**Tech Stack**
- **Runtime:** .NET 8, 9 and 10, ASP.NET Core minimal APIs, dependency injection, Server-Sent Events
- **Standards:** OpenID4VP 1.0, DCQL, JAR (RFC 9101), SD-JWT VC with KB-JWT, mso_mdoc (ISO 18013-5/-7), Token Status List
- **Cryptography:** JOSE / JWT, CBOR / COSE for mdoc, ECDH-ES encrypted responses, Azure Key Vault / HSM signing
- **Packages:** Core, Core.Mdoc, OpenId4Vp, AspNetCore and Trust
- **Quality:** nullable, warnings-as-errors, more than 200 tests across five suites, CI, NuGet with symbols

**Approach & Highlights**
- First .NET-native EUDI verifier, no port from Kotlin or Rust
- Demo, Mock, Test and Live modes so teams build before wallets ship
- SD-JWT VC and mdoc verified through one pipeline, encrypted responses included
- Conformance-validated against the RFC 9901 vector and an independent mdoc implementation
- Clear path to production via a managed trust layer, with no HSM on the relying-party side

---

# Tessio.Verifier — Plattformssammanfattning (Svenska)

Tessio.Verifier är ett **.NET / ASP.NET Core**-bibliotek med öppen källkod för att verifiera uppgifter från **EU:s digitala identitetsplånböcker (EUDI Wallet)**, på den förlitande partens sida. Det implementerar **OpenID4VP 1.0** med uppgifter i formaten **SD-JWT VC** och **mdoc** (ISO 18013-5/-7, mobilt körkort), och agerar aldrig plånbok eller utfärdare. Det byggs av **Triple Down AB** och publiceras på NuGet under **Apache-2.0**, och kopplas in i ASP.NET Core via dependency injection och minimala API-ändpunkter, så att det ser ut som resten av teamets .NET-stack.

Det finns på grund av en tydlig tidsgräns. Enligt **förordning (EU) 2024/1183 (eIDAS 2.0)** måste medlemsstaterna leverera en certifierad EUDI-plånbok senast **december 2026** och reglerade förlitande parter måste acceptera den senast **december 2027**. Befintliga verktyg med öppen källkod finns i Kotlin, Rust och TypeScript, så .NET-team har saknat ett inbyggt alternativ tills nu. Fyra lägen låter team bygga innan riktiga plånböcker finns: **Demo** slutför lokalt, **Mock** kör en inbyggd plånbok genom hela pipelinen, **Test** spelar upp specvektorn i RFC 9901 och **Live** betjänar riktiga plånböcker med signerade förfrågningar och krypterade svar.

I produktion behöver en förlitande part ett **WRPAC**-certifikat (ETSI TS 119 475) och måste validera EU:s tillitshierarki i alla 27 medlemsstater. Biblioteket isolerar detta bakom ett enda **`ITrustListResolver`**-gränssnitt, och ett förvaltat lager tillhandahåller registrering, WRPAC och levande tillitslistor, utan krav på HSM hos den förlitande parten.

**Teknikstack**
- **Körmiljö:** .NET 8, 9 och 10, ASP.NET Core minimala API:er, dependency injection, Server-Sent Events
- **Standarder:** OpenID4VP 1.0, DCQL, JAR (RFC 9101), SD-JWT VC med KB-JWT, mso_mdoc (ISO 18013-5/-7), Token Status List
- **Kryptografi:** JOSE / JWT, CBOR / COSE för mdoc, ECDH-ES-krypterade svar, signering via Azure Key Vault / HSM
- **Paket:** Core, Core.Mdoc, OpenId4Vp, AspNetCore och Trust
- **Kvalitet:** nullbara typer, varningar som fel, fler än 200 tester över fem sviter, CI, NuGet med symboler

**Angreppssätt & höjdpunkter**
- Första .NET-inbyggda EUDI-verifieraren, ingen översättning från Kotlin eller Rust
- Lägena Demo, Mock, Test och Live så att team bygger innan plånböckerna finns
- SD-JWT VC och mdoc verifieras genom samma pipeline, inklusive krypterade svar
- Konformansvaliderad mot RFC 9901-vektorn och en oberoende mdoc-implementation
- Tydlig väg till produktion via ett förvaltat tillitslager, utan HSM hos den förlitande parten
