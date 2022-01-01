package br.com.crazycrowd.openssh.decrypter;

import br.com.crazycrowd.openssh.kdf.OpenSSHKDF;
import br.com.crazycrowd.openssh.kdf.OpenSSHKDFOptions;

import java.security.GeneralSecurityException;

public interface OpenSSHDecrypter {

  byte[] decrypt(
      final byte[] encrypted,
      final String passphrase,
      final OpenSSHKDFOptions kdfOptions,
      final OpenSSHKDF kdf
  ) throws GeneralSecurityException;

}
