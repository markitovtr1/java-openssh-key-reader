package br.com.crazycrowd.openssh.keys;

import java.util.HashMap;
import java.util.Map;

/**
 * Extracted from `sshkey.c` keytypes static array
 * https://github.com/openssh/openssh-portable/blob/ef5916b8acd9b1d2f39fad4951dae03b00dbe390/sshkey.c#L106
 */
public enum OpenSSHAsymmetricKeyType {

  DSA("ssh-dss"),
  DSA_CERT("ssh-dss-cert-v01@openssh.com"),
  ECDSA_256("ecdsa-sha2-nistp256"),
  ECDSA_256_CERT("ecdsa-sha2-nistp256-cert-v01@openssh.com"),
  ECDSA_256_SK("sk-ecdsa-sha2-nistp256@openssh.com"),
  ECDSA_256_SK_CERT("sk-ecdsa-sha2-nistp256-cert-v01@openssh.com"),
  ECDSA_384("ecdsa-sha2-nistp384"),
  ECDSA_384_CERT("ecdsa-sha2-nistp384-cert-v01@openssh.com"),
  ECDSA_521("ecdsa-sha2-nistp521"),
  ECDSA_521_CERT("ecdsa-sha2-nistp521-cert-v01@openssh.com"),
  ED25519("ssh-ed25519", ED25519KeyReader.getInstance()),
  ED25519_CERT("ssh-ed25519-cert-v01@openssh.com"),
  ED25519_SK("sk-ssh-ed25519@openssh.com"),
  ED25519_SK_CERT("sk-ssh-ed25519-cert-v01@openssh.com"),
  RSA("ssh-rsa"),
  RSA_CERT("ssh-rsa-cert-v01@openssh.com"),
  RSA_SHA2_256("rsa-sha2-256"),
  RSA_SHA2_256_CERT("rsa-sha2-256-cert-v01@openssh.com"),
  RSA_SHA2_512("rsa-sha2-512"),
  RSA_SHA2_512_CERT("rsa-sha2-512-cert-v01@openssh.com"),
  WEBAUTHN_ECDSA_256("webauthn-sk-ecdsa-sha2-nistp256@openssh.com"),
  XMSS("ssh-xmss@openssh.com"),
  XMSS_CERT("ssh-xmss-cert-v01@openssh.com");

  public final String typeName;
  public final OpenSSHAsymmetricKeyReader keyReader;
  private static final Map<String, OpenSSHAsymmetricKeyType> typeNameToEnumMap;

  OpenSSHAsymmetricKeyType(final String typeName) {
    this(typeName, new UnsupportedKeyReader(typeName));
  }

  OpenSSHAsymmetricKeyType(
      final String typeName,
      final OpenSSHAsymmetricKeyReader keyReader
  ) {
    this.typeName = typeName;
    this.keyReader = keyReader;
  }

  static {
    typeNameToEnumMap = new HashMap<>();

    for (OpenSSHAsymmetricKeyType asymmetricKeyType : values()) {
      typeNameToEnumMap.put(asymmetricKeyType.typeName, asymmetricKeyType);
    }
  }

  public static OpenSSHAsymmetricKeyType getFromTypeNameString(
      final String typeName
  ) {
    final OpenSSHAsymmetricKeyType asymmetricKeyType =
        typeNameToEnumMap.get(typeName);

    if (asymmetricKeyType == null) {
      throw new RuntimeException("OpenSSH Asymmetric Key Type not found for name " + typeName);
    }

    return asymmetricKeyType;
  }

}
