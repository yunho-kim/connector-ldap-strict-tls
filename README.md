# LDAP connector with strict configured-host TLS verification

Independent community fork of [Evolveum's LDAP/AD ConnId connector](https://github.com/Evolveum/connector-ldap),
based on commit `cde24ae9657a3cc124a9554131e283a0685cff61` (3.10).
This project is not an official Evolveum release and is not endorsed by Evolveum.

Version: **3.10.2-hyse-strict-tls**. License: **Apache-2.0**, with the upstream notices retained.

## Changes

* Apache Directory LDAP API is updated from 2.1.6 to **2.1.9**, which includes upstream security corrections.
* A trust-manager wrapper retains the original JSSE/PKIX trust decision and then checks the **configured** DNS name or IP SAN.
* Endpoint identity is not inferred from reverse DNS, a resolved address, or an unrelated certificate CN when SANs are present.
* Apache HttpClient5's hostname verifier supplies DNS/IP identity matching.
* The upstream ConnId **1.7.0.0-M0** framework is explicitly pinned. Its classes require **JDK21+**.

The runtime changes are limited to `pom.xml`, `ConfiguredHostTrustManager.java`, and `ServerConnectionPool.java`.
They do not change account provisioning policy, directory schema, or the connector's public configuration property names.

## Build and tests

Use a JDK 21 or later and Maven (the source target is 17, but ConnId itself requires 21):

```sh
mvn -B -ntp -Dproject.build.outputTimestamp=2026-11-08T00:00:00Z package
```

The connector bundle is written to `target/connector-ldap-3.10.2-hyse-strict-tls.jar`.

The default suite includes upstream utility/schema and embedded OpenDJ tests, together with new TLS boundary tests.
New certificates and private keys are generated locally under ignored `target/` paths and are never checked in.
The new tests cover matching and mismatched DNS/IPv4/IPv6 SANs, missing configured identity, untrusted certificates,
CN/SAN precedence, a localhost/address alias mismatch, and actual TLS handshakes over loopback.
No external LDAP credentials are supplied by the default build. Upstream `TestAD` requires explicit external configuration
and is skipped when that configuration is absent; a skip is not evidence of Microsoft AD compatibility.

Unmodified upstream OpenDJ fixture keystores, database, and sample credentials under `src/test/resources/opendj-template/`
are public synthetic test fixtures from the pinned upstream source. Use them only for isolated tests.
No deployment configuration, real account, private certificate, operational credential, or directory backup is included.

## Use and compatibility

The runtime patch was exercised with **midPoint 4.11.0** and **Samba AD DC 4.23.13** in isolated tests.
Those checks included trusted/mismatched DNS and IP identities, untrusted CA rejection, provisioning, and expiry.
This does not certify all LDAP servers, all midPoint versions, production deployments, or all possible vulnerabilities.
Use the public CI results for the exact source revision's build/test status.

Deploy the connector using midPoint's normal external-connector mechanism. Discover the new connector and select its exact
bundle/version in each resource; do not assume existing resource references automatically select it.
For AD resources the Java class is:

```text
com.evolveum.polygon.connector.ldap.ad.AdLdapConnector
```

For generic LDAP resources it is:

```text
com.evolveum.polygon.connector.ldap.LdapConnector
```

Use a trusted CA, configure the exact intended DNS/IP endpoint, and keep `allowUntrustedSsl=false`.
Re-run positive and negative TLS checks through the actual configured resource before using provisioning.
Review the generated bundle/dependency notices before redistribution.

## MidPoint Integration Catalog

Publication of this repository alone does **not** mean the connector is approved or validated in the Integration Catalog.
The [official procedure](https://docs.evolveum.com/connectors/integration-catalog/share-connectors/validate-connector/)
requires a contributor submission, Evolveum's build/publication, and validation of the resulting connector sheet in midPoint.
There is no change to midPoint's subscription checks, connector validation, or evaluation-period handling in this repository.
Catalog acceptance and processing time are controlled by Evolveum.

## Maintenance

Track upstream LDAP connector releases and Apache Directory security advisories. Prefer an upstream release incorporating
the required corrections when it passes the same deployment tests. On a dependency or runtime update, repeat the TLS
matrix and the target-directory lifecycle/failover/restore tests. A successful local build is not vendor support.

Use this repository's issues for ordinary bugs. Do not post deployment secrets or undisclosed vulnerabilities in public issues.
