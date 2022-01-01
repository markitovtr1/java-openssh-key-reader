package br.com.crazycrowd.openssh.kdf;

import java.util.HashMap;
import java.util.Map;

/**
 * Extracted from PROTOCOL.key file (check README.md for file link)
 */
public enum OpenSSHKDFType {

  BCRYPT("bcrypt", BCryptKDF.getInstance()),
  NONE("none", NoneKDF.getInstance());

  public final String kdfName;
  public final OpenSSHKDF kdf;
  private static final Map<String, OpenSSHKDFType> kdfNameToEnumMap;

  OpenSSHKDFType(final String kdfName, final OpenSSHKDF kdf) {
    this.kdfName = kdfName;
    this.kdf = kdf;
  }

  static {
    kdfNameToEnumMap = new HashMap<>();

    for (final OpenSSHKDFType supportedKdf : values()) {
      kdfNameToEnumMap.put(supportedKdf.kdfName, supportedKdf);
    }
  }

  public static OpenSSHKDFType getFromKdfNameString(final String kdfName) {
    final OpenSSHKDFType kdf = kdfNameToEnumMap.get(kdfName);

    if (kdf == null) {
      throw new RuntimeException("OpenSSH KDF not found for name " + kdfName);
    }

    return kdf;
  }

}
