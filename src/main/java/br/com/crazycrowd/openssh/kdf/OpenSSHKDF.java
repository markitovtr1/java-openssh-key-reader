package br.com.crazycrowd.openssh.kdf;

public interface OpenSSHKDF {

  byte[] deriveKey(byte[] password, byte[] salt, int rounds, int sizeInBytes);

  OpenSSHKDFOptions readOptions(final byte[] kdfOptions);

}
