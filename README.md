# Encryption Tools Java Bindings

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Java bindings for cryptographic tools library, specifically designed to support Global Travel Rule compliance
requirements.

## Features

- Complete Java bindings for cryptographic functions
- Support for Travel Rule compliant encryption algorithms -
  see [EncryptionAlgorithm](core/src/main/java/com/globaltravelrule/encryption/core/enums/EncryptionAlgorithm.java)
    - ed25519_curve25519: ed25519 with curve25519 cipher
    - keccak256: keccak256 hash with salt
    - rsa_ecb_oaep_with_sha1_and_mgf1padding: rsa ecb oaep with sha1 and mgf1 padding encryption
    - ecies_secp256r1
    - ecies_secp384r1
    - ecies_secp521r1
    - ecies_secp256k1
    - ecies_sect571k1
  - ecies_secp384r1_tubitak
- Simple and intuitive Java API
- Encryption and decryption support full-text, field, or recursive JSON string fields -
  see [EncryptionFormat.java](core/src/main/java/com/globaltravelrule/encryption/core/enums/EncryptionFormat.java)
- Cross-platform support (Windows/Linux/macOS)
- Cross-architecture support (X86/X64/ARM)
- Automatic native library loading

## Quick Start

### Requirements

- Java 11 or higher

### Installation

#### Maven

```xml

<project>
    <repositories>
        <repository>
            <id>global-travel-rule-github-public</id>
            <name>Global Travel Rule GitHub Public Packages</name>
            <url>https://maven.pkg.github.com/Global-Travel-Rule/encryption-tools</url>
            <!-- public repository -->
            <releases>
                <enabled>true</enabled>
            </releases>
            <snapshots>
                <enabled>true</enabled>
            </snapshots>
        </repository>
    </repositories>

    <dependencies>
        <!-- globaltravelrule encryption dependency -->

        <!-- api core -->
        <dependency>
            <groupId>com.globaltravelrule.encryption</groupId>
            <artifactId>core</artifactId>
            <version>{LATEST_VERSION}</version>
        </dependency>

        <!-- default global travel rule implementation -->
        <dependency>
            <groupId>com.globaltravelrule.encryption</groupId>
            <artifactId>global-travel-rule-impl</artifactId>
            <version>{LATEST_VERSION}</version>
        </dependency>
    </dependencies>
</project>
```

#### Gradle

```groovy

implementation 'com.globaltravelrule.encryption:core:{LATEST_VERSION}'
implementation 'com.globaltravelrule.encryption:global-travel-rule-impl:{LATEST_VERSION}'
```

### Usage

#### Basic com.globaltravelrule.encryption.Example

```java
import com.globaltravelrule.encryption.core.enums.EncryptionAlgorithm;
import com.globaltravelrule.encryption.core.enums.EncryptionFormat;
import com.globaltravelrule.encryption.core.options.EncryptionKeyPair;
import com.globaltravelrule.encryption.core.options.KeyInfo;
import com.globaltravelrule.encryption.core.options.PiiSecuredInfo;

public class Example {

    public static void main(String[] args) {
        // Initialize key pair
        EncryptionKeyPair aliceKp = EncryptionUtils.generateEncryptionKeyPair(EncryptionAlgorithm.ED25519_CURVE25519.getName());
        EncryptionKeyPair bobKp = EncryptionUtils.generateEncryptionKeyPair(EncryptionAlgorithm.ED25519_CURVE25519.getName());
        System.out.println("alice key pair: " + aliceKp.getBase64PublicKey() + ", " + aliceKp.getBase64privateKey());
        System.out.println("bob key pair: " + bobKp.getBase64PublicKey() + ", " + bobKp.getBase64privateKey());

        String originalMessage = "{\"test_num1\":0,\"test_num2\":1.01,\"test_bool\":true,\"test_string\":\"testing\",\"testing_object\":{\"testing_object_num1\":0,\"testing_object_num2\":1.01,\"testing_object_bool\":true,\"testing_object_string\":\"testing\"}}";
        System.out.println("raw message: " + originalMessage);

      PiiSecuredInfo piiSecuredInfo = new PiiSecuredInfo();
      piiSecuredInfo.setSecretAlgorithm(EncryptionAlgorithm.ED25519_CURVE25519.getName());
      piiSecuredInfo.setPiiSecretFormatType(EncryptionFormat.FULL_JSON_OBJECT_ENCRYPT.getFormat());

      // encrypt message
      piiSecuredInfo.setInitiatorKeyInfo(new KeyInfo(aliceKp.getBase64PublicKey(), aliceKp.getBase64privateKey()));
      piiSecuredInfo.setReceiverKeyInfo(new KeyInfo(bobKp.getBase64PublicKey(), bobKp.getBase64privateKey()));
      piiSecuredInfo.setSecuredPayload(null);

      String encryptedMessage = EncryptionUtils.encrypt(piiSecuredInfo, originalMessage).getSecuredPayload();
      System.out.printf("encrypted message(%s): %s%n", piiSecuredInfo.getPiiSecretFormatType(), encryptedMessage);

        // decrypt message
      String decryptedMessage = EncryptionUtils.decrypt(piiSecuredInfo);
        System.out.println("decrypted message: " + decryptedMessage);

        assert originalMessage.equals(decryptedMessage);
    }
}
```

### API Reference

#### Key Generation, Encryption and Decryption

- `com.globaltravelrule.encryption.core.EncryptionUtils.generateEncryptionKeyPair`: Generates a new key pair for the
  specified method.
- `com.globaltravelrule.encryption.core.EncryptionUtils.encrypt`: Encrypts a message using the specified method and key
  pair.
- `com.globaltravelrule.encryption.core.EncryptionUtils.decrypt`: Decrypts an encrypted message using the specified
  method and key pair.

### Development

#### Build Project

```shell
  mvn clean package
```

#### Run Tests

```shell
  mvn clean test
```

### Contribution Workflow

1. Fork the repository

2. Create feature branch (git checkout -b feature/xyz)

3. Commit changes (git commit -am 'Add feature xyz')

4. Push to branch (git push origin feature/xyz)

5. Open Pull Request

### License

MIT License - See [LICENSE](LICENSE) for details.

### Support

- Report issues at: \
  https://github.com/Global-Travel-Rule/encryption-tools/issues

