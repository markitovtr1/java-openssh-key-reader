package br.com.crazycrowd.openssh.keys;

import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

public interface OpenSSHAsymmetricKeyReader {

  PublicKey readPublicKey(final byte[] publicKeyBytes) throws InvalidKeySpecException;

  /**
   * Reads a private key from a buffer, right after reading key type on OpenSSH
   * format.
   * <p>
   * Check `The OpenSSH private key binary format` on README.md to learn more
   * about this.
   *
   * @param byteBuffer Buffer right after keyType string on decrypted private
   *                   key section
   * @return PrivateKey
   * @throws InvalidKeySpecException
   */
  PrivateKey readPrivateKey(final ByteBuffer byteBuffer) throws InvalidKeySpecException;

}
