package br.com.crazycrowd.openssh.kdf;

public class OpenSSHKDFOptions {

  public final byte[] salt;
  public final int rounds;

  public OpenSSHKDFOptions(final byte[] salt, final int rounds) {
    this.salt = salt;
    this.rounds = rounds;
  }

}
