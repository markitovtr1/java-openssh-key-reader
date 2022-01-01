package br.com.crazycrowd.openssh.kdf;

import br.com.crazycrowd.openssh.ByteBufferUtils;
import org.mindrot.jbcrypt.BCrypt;

import java.nio.ByteBuffer;

public class BCryptKDF implements OpenSSHKDF {

  private static final BCrypt BCRYPT = new BCrypt();
  private static final BCryptKDF kdf = new BCryptKDF();

  private BCryptKDF() {
  }

  public static BCryptKDF getInstance() {
    return kdf;
  }

  @Override
  public byte[] deriveKey(byte[] password, byte[] salt, int rounds, int sizeInBytes) {
    final byte[] derivedKey = new byte[sizeInBytes];

    BCRYPT.pbkdf(password, salt, rounds, derivedKey);

    return derivedKey;
  }

  @Override
  public OpenSSHKDFOptions readOptions(final byte[] kdfOptions) {
    final ByteBuffer buffer = ByteBuffer.wrap(kdfOptions);
    final byte[] salt = ByteBufferUtils.readStringBytes(buffer);
    final int rounds = buffer.getInt();

    return new OpenSSHKDFOptions(salt, rounds);
  }

}
