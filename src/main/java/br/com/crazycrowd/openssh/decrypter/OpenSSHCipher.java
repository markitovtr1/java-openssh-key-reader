package br.com.crazycrowd.openssh.decrypter;

import java.util.HashMap;
import java.util.Map;

/**
 * Extracted from https://www.ssh.com/academy/ssh/sshd_config#detailed-sshd_config-file-format
 * <p>
 * Check "Cipher" section.
 */
public enum OpenSSHCipher {

  TRIPLE_DES_CBC("3des-cbc"),
  AES_128_CBC("aes128-cbc"),
  AES_192_CBC("aes192-cbc"),
  AES_256_CBC("aes256-cbc"),
  AES_128_CTR("aes128-ctr"),
  AES_192_CTR("aes192-ctr"),
  AES_256_CTR("aes256-ctr", Aes256CtrDecrypter.getInstance()),
  AES_128_GCM("aes128-gcm@openssh.com"),
  AES_256_GCM("aes256-gcm@openssh.com"),
  ARCFOUR("arcfour"),
  ARCFOUR_128("arcfour128"),
  ARCFOUR_256("arcfour256"),
  BLOW_FISH_CBC("blowfish-cbc"),
  CAST_128_CBC("cast128-cbc"),
  CHACHA_20_POLY_1305("chacha20-poly1305@openssh.com"),
  NONE("none", NoneDecrypter.getInstance());

  public final String algorithm;
  public final OpenSSHDecrypter decrypter;
  private static final Map<String, OpenSSHCipher> algorithmToEnumMap;

  OpenSSHCipher(final String algorithm) {
    this(algorithm, new UnsupportedDecrypter(algorithm));
  }

  OpenSSHCipher(final String algorithm, final OpenSSHDecrypter decrypter) {
    this.algorithm = algorithm;
    this.decrypter = decrypter;
  }

  static {
    algorithmToEnumMap = new HashMap<>();

    for (final OpenSSHCipher supportedCipher : values()) {
      algorithmToEnumMap.put(supportedCipher.algorithm, supportedCipher);
    }
  }

  public static OpenSSHCipher getFromAlgorithmString(final String algorithm) {
    final OpenSSHCipher cipher = algorithmToEnumMap.get(algorithm);

    if (cipher == null) {
      throw new RuntimeException(
          "OpenSSH cipher not found for algorithm " + algorithm
      );
    }

    return cipher;
  }

}
