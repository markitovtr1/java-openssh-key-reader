package br.com.crazycrowd.openssh.keys;

import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;

public class UnsupportedKeyReader implements OpenSSHAsymmetricKeyReader {

  private final UnsupportedOperationException unsupportedException;

  public UnsupportedKeyReader(final String asymmetricKeyType) {
    this.unsupportedException = new UnsupportedOperationException(
        asymmetricKeyType + " not supported"
    );
  }

  @Override
  public PublicKey readPublicKey(final byte[] publicKeyBytes) {
    throw unsupportedException;
  }

  @Override
  public PrivateKey readPrivateKey(final ByteBuffer byteBuffer) {
    throw unsupportedException;
  }

}
