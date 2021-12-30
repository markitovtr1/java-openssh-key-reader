# OpenSSH KeyReader

Since newer versions of OpenSSH, assymetric keys are generated by default in a new format. Unfortunately, very few
libraries are able to read this new specific format into JCE (Java Cryptography Extension) APIs. To help that, this
small library reads this format into PublicKey and PrivateKey.

This lib expect OpenSSH keys to be small enough to not be a problem to load the entire file in memory. Since this format
allows multiple keys to be able save in the same file, keep that in mind when using this library.

## About Security Provider

This library objective is to be as lightweight as possible, so pure Java implementation with minimal dependencies. You
might need to add EdDSASecurityProvider in case you are using older versions of Java, as JRE do not come with ED25519
implementation on JCE.

Sample error you might see:

`java.security.NoSuchAlgorithmException: XXXX KeyFactory not available`

To add mentioned provider, at the beginning of your application, add the following code:

`java.security.Security.addProvider(new EdDSASecurityProvider());`

If you do not like using a dynamic configuration like that, you can add this in a more transparent way,
via `java.security` file or any other way JCE allows. Here are some links that might be helpful in case you want to read
more about this and fix further possible errors:

- [Java 6](https://docs.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html#CoreClasses)
- [Java 11](https://docs.oracle.com/en/java/javase/11/security/howtoimplaprovider.html#GUID-831AA25F-F702-442D-A2E4-8DA6DEA16F33)
- [Java 17](https://docs.oracle.com/en/java/javase/17/security/howtoimplaprovider.html#GUID-FB9C6DB2-DE9A-4EFE-89B4-C2C168C5982D)

## Format specification

You can check it
in [OpenSSH GitHub.](https://github.com/openssh/openssh-portable/blob/2dc328023f60212cd29504fc05d849133ae47355/PROTOCOL.key)

`string` field is not a C String, ending in `\0`, but rather an array of bytes, where first byte is the array length in
uint32. Take that in mind when trying to understand reading code in this repository.

If you want to know how OpenSSH writes types,
check `sshbuf-getput-basic.c` [in their repo](https://github.com/openssh/openssh-portable/blob/2dc328023f60212cd29504fc05d849133ae47355/sshbuf-getput-basic.c)

Something extra, that is not written on `PROTOCOL.key`: Depending on key type, SSH writes `privateKey` section
differently. To implement correctly for each key type, unfortunately, you'll have to read OpenSSH code. Search for
functions `sshkey_private_to_blob2` and `to_blob_buf` inside `sshkey.c`
file [in their repo](https://github.com/openssh/openssh-portable/blob/ef5916b8acd9b1d2f39fad4951dae03b00dbe390/sshkey.c)

To learn more about symmetric key encryption used,
check `cipher.c` [in their repo](https://github.com/openssh/openssh-portable/blob/2dc328023f60212cd29504fc05d849133ae47355/cipher.c)

Feel free to look some articles on this structure:

- [The OpenSSH private key binary format](http://dnaeon.github.io/openssh-private-key-binary-format/)
- [Public key cryptography: OpenSSH private keys](https://www.thedigitalcatonline.com/blog/2021/06/03/public-key-cryptography-openssh-private-keys/)

## Supported keys

This library is guaranteed to work with ED25519 OpenSSH key with a single key inside and AES 256 CTR mode or no
passphrase. It should work with multiple keys as well, but there aren't tests for this scenario. Feel free to add a test
case scenario for this here.

If you need support for other algorithms, please contribute!

## Testing

Use `./gradlew test` to run tests.

### Commands used to generate test keys

```sh
ssh-keygen -t ed25519 -C ''
```

Passphrases used are in format `${ALGORITHM_NAME}123`. Replace `${ALGORITHM_NAME}` with:

- ed25519

## Importing this library

This lib is not published yet on Maven Central. Use gradle source dependencies or equivalent in maven to use this.

* [Gradle instructions here](https://blog.gradle.org/introducing-source-dependencies)
