package br.com.crazycrowd.openssh;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class OpenSSHKeyReaderTest {

  private static final Provider ED_DSA = new EdDSASecurityProvider();
  private static final Path resources = Path.of("src", "test", "resources");
  private static final OpenSSHKeyReader reader =
      OpenSSHKeyReader.getInstance();

  @BeforeAll
  public static void addBouncyCastleProvider() {
    Security.addProvider(ED_DSA);
  }

  @AfterAll
  public static void removeBouncyCastleProvider() {
    Security.removeProvider(ED_DSA.getName());
  }

  @Test
  public void readsEd25519KeyWithPassphrase() throws Exception {
    final String testKeyName = "ed25519_with_passphrase.key";
    final List<KeyPair> keyPairs =
        reader.readFile(resources.resolve(testKeyName), "ed25519123");

    assertThat(keyPairs).hasSize(1);
    assertPublicKeyIsReadCorrectly(
        "ssh-ed25519",
        testKeyName + ".pub",
        keyPairs.get(0).getPublic().getEncoded()
    );

    assertKeysMatch("NONEwithEdDSA", keyPairs.get(0));
  }

  @Test
  public void readsEd25519KeyWithoutPassphrase() throws Exception {
    final String testKeyName = "ed25519_without_passphrase.key";
    final List<KeyPair> keyPairs =
        reader.readFile(resources.resolve(testKeyName));

    assertThat(keyPairs).hasSize(1);
    assertPublicKeyIsReadCorrectly(
        "ssh-ed25519",
        testKeyName + ".pub",
        keyPairs.get(0).getPublic().getEncoded()
    );
    assertKeysMatch("NONEwithEdDSA", keyPairs.get(0));
  }

  private void assertPublicKeyIsReadCorrectly(
      final String publicKeyPrefix,
      final String publicKeyFile,
      final byte[] readPublicKeyBytes
  ) throws IOException {
    final String publicFileKey =
        Files.readString(resources.resolve(publicKeyFile));
    final String publicKeyBase64 = publicFileKey.substring(
        publicKeyPrefix.length() + 1 // removing keytype prefix and space
    );

    final byte[] publicKeyBytesWithHeaders =
        Base64.getDecoder().decode(publicKeyBase64.trim());
    final byte[] publicKeyBytes = Arrays.copyOfRange(
        publicKeyBytesWithHeaders,
        // removes keyType length int, keyType bytes and keySize length
        publicKeyPrefix.length() + 8,
        publicKeyBytesWithHeaders.length
    );

    // Removing prefix [48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0]
    // Not sure why there is that on `getEncoded()`
    final byte[] readPublicKeyBytesWithoutPrefix =
        Arrays.copyOfRange(readPublicKeyBytes, 12, readPublicKeyBytes.length);

    assertThat(readPublicKeyBytesWithoutPrefix)
        .containsExactly(publicKeyBytes);
  }

  private void assertKeysMatch(
      final String transformation,
      final KeyPair keyPair
  ) throws GeneralSecurityException {
    final byte[] testBytes = {0, 1, 2, 3, 4, 5};

    final Signature signer = Signature.getInstance(transformation);
    signer.initSign(keyPair.getPrivate());
    signer.update(testBytes);
    final byte[] signature = signer.sign();

    final Signature verifier = Signature.getInstance(transformation);
    verifier.initVerify(keyPair.getPublic());
    verifier.update(testBytes);

    assertThat(verifier.verify(signature)).isTrue();
  }

}
