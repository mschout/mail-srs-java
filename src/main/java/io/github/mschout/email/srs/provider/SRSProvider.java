package io.github.mschout.email.srs.provider;

import io.github.mschout.email.srs.SRSAddress;
import java.security.InvalidKeyException;

public interface SRSProvider {
  boolean isSRS0(String address);

  boolean isSRS1(String address);

  String compile(String host, String user) throws InvalidKeyException;

  SRSAddress parse(String srsAddress);

  String getSecret();

  String getSeparator();
}
