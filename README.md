# mail-srs-java

A Java/Kotlin implementation of the [Sender Rewriting Scheme (SRS)](https://en.wikipedia.org/wiki/Sender_Rewriting_Scheme) for email.

SRS rewrites the envelope sender address of forwarded emails so that they pass
[SPF](https://en.wikipedia.org/wiki/Sender_Policy_Framework) checks at the
next hop. Without SRS, forwarded mail is likely to be rejected because the
forwarding server is not authorized to send on behalf of the original sender's
domain.

## Installation

Replace `VERSION` with the latest release version.

### Gradle (Kotlin DSL)

```kotlin
dependencies {
    implementation("io.github.mschout:mail-srs-java:VERSION")
}
```

### Gradle (Groovy DSL)

```groovy
dependencies {
    implementation 'io.github.mschout:mail-srs-java:VERSION'
}
```

### Maven

```xml
<dependency>
    <groupId>io.github.mschout</groupId>
    <artifactId>mail-srs-java</artifactId>
    <version>VERSION</version>
</dependency>
```

## Requirements

- Java 17 or later

## Usage

### Quick Start

```java
import io.github.mschout.email.srs.SRS;

// Create an SRS instance with a shared secret
SRS srs = SRS.guardedSRS(List.of("my-secret-key"));

// Rewrite a sender address for forwarding through alias.com
String rewritten = srs.forward("user@example.com", "alias.com");
// Result: SRS0=HHH=TT=example.com=user@alias.com

// Reverse an SRS address back to the original sender
String original = srs.reverse(rewritten);
// Result: user@example.com

// Check if an address is SRS-rewritten
boolean isSrs = srs.isSRS(rewritten); // true
```

### Kotlin

```kotlin
import io.github.mschout.email.srs.SRS

val srs = SRS.guardedSRS(listOf("my-secret-key"))

val rewritten = srs.forward("user@example.com", "alias.com")
val original = srs.reverse(rewritten)
```

### SRS Types

Three SRS implementations are available, with increasing levels of protection:

| Type | Description |
|------|-------------|
| `SHORTCUT` | Simple rewriting with minimal transformation |
| `REVERSIBLE` | Adds timestamp-based age validation |
| `GUARDED` | Full hash and timestamp validation to prevent tampering (recommended) |

```java
SRS srs = new SRS(SRS.Type.GUARDED, "my-secret-key");
```

### Key Rotation

Multiple secrets can be provided. The first secret is used for signing new
addresses; all secrets are accepted when validating incoming SRS addresses.

```java
SRS srs = SRS.guardedSRS(List.of("current-secret", "previous-secret"));
```

### Custom Configuration

Use `SRSProviderFactory` for fine-grained control over hashing and timestamp
parameters:

```java
import io.github.mschout.email.srs.SRS;
import io.github.mschout.email.srs.provider.SRSProviderFactory;

var provider = SRSProviderFactory.builder()
    .maxAge(30)          // Max age in days (default: 49)
    .hashLength(5)       // Hash length (default: 4)
    .hashMinLength(4)    // Minimum acceptable hash length (default: 4)
    .separator("=")      // Separator character: =, +, or - (default: =)
    .build()
    .createProvider(SRS.Type.GUARDED, List.of("my-secret"));

SRS srs = new SRS(provider);
```

## How SRS Works

When an email is forwarded, SRS rewrites the envelope sender so the forwarding
domain takes responsibility for the bounce address:

1. **SRS0** (first hop): `user@example.com` forwarded through `alias.com` becomes
   `SRS0=HHH=TT=example.com=user@alias.com`
2. **SRS1** (subsequent hops): If an already-rewritten SRS0 address is forwarded
   again, it is wrapped in an SRS1 envelope to preserve the chain.

The hash (`HHH`) prevents tampering, and the timestamp (`TT`) allows the
receiving server to reject stale addresses.

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)
