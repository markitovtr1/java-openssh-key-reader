package br.com.crazycrowd.openssh.decrypter;

import br.com.crazycrowd.openssh.kdf.OpenSSHKDF;
import br.com.crazycrowd.openssh.kdf.OpenSSHKDFOptions;

public class UnsupportedDecrypter implements OpenSSHDecrypter {

  private final UnsupportedOperationException unsupportedException;

  public UnsupportedDecrypter(final String cipherName) {
    this.unsupportedException = new UnsupportedOperationException(
        "Cipher not yet supported: " + cipherName
    );
  }

  @Override
  public byte[] decrypt(
      final byte[] encrypted,
      final String passphrase,
      final OpenSSHKDFOptions kdfOptions,
      final OpenSSHKDF kdf
  ) {
    throw unsupportedException;
  }

}
