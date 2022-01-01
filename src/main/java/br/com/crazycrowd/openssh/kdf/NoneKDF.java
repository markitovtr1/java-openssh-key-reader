package br.com.crazycrowd.openssh.kdf;

public class NoneKDF implements OpenSSHKDF {

  private static final NoneKDF kdf = new NoneKDF();

  private NoneKDF() {
  }

  public static NoneKDF getInstance() {
    return kdf;
  }

  @Override
  public byte[] deriveKey(byte[] password, byte[] salt, int rounds, int sizeInBytes) {
    return new byte[0];
  }

  @Override
  public OpenSSHKDFOptions readOptions(final byte[] kdfOptions) {
    return null;
  }

}
