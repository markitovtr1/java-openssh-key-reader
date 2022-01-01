package br.com.crazycrowd.openssh.decrypter;

import br.com.crazycrowd.openssh.kdf.OpenSSHKDF;
import br.com.crazycrowd.openssh.kdf.OpenSSHKDFOptions;

public class NoneDecrypter implements OpenSSHDecrypter {

  private static final NoneDecrypter decrypter = new NoneDecrypter();

  private NoneDecrypter() {
  }

  @Override
  public byte[] decrypt(
      final byte[] encrypted,
      final String passphrase,
      final OpenSSHKDFOptions kdfOptions,
      final OpenSSHKDF kdf
  ) {
    return encrypted;
  }

  public static NoneDecrypter getInstance() {
    return decrypter;
  }

}
