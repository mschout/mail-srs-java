package io.github.mschout.email.srs.provider;

import com.google.common.base.CharMatcher;
import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableList;
import io.github.mschout.email.srs.SRSAddress;
import java.security.InvalidKeyException;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

public class GuardedSRSProvider extends ShortCutSRSProvider implements SRSProvider {

  public GuardedSRSProvider(List<String> secrets) {
    super(secrets);
  }

  @Override
  public SRSAddress parse(String srsAddress) {
    if (isSRS1(srsAddress)) {
      String address = removePrefix(srsAddress);

      Iterator<String> addressIter = Splitter.on(SRSSEP).limit(3).split(address).iterator();

      try {
        String hash = addressIter.next();
        String host = addressIter.next();
        String user = addressIter.next();

        if (isHashInvalid(ImmutableList.of(host, user), hash)) throw new IllegalArgumentException("Invalid SRS1 Address: " + srsAddress);

        if (host.isEmpty()) throw new IllegalArgumentException("Invalid SRS1 Address: " + srsAddress);

        // here we stick SRS0 tag in front of user as we are reversing the SRS1 address back to the SRS0 tag
        // when we parsed teh SRS0 address, we stripped the tag but left the separator in place
        return new SRSAddress(SRSPrefix.SRS1, host, SRSPrefix.SRS0 + user, hash);
      } catch (NoSuchElementException e) {
        throw new IllegalArgumentException("Invalid SRS1 Address: " + srsAddress);
      }
    }

    return super.parse(srsAddress);
  }

  @Override
  public String compile(String host, String user) throws InvalidKeyException {
    if (isSRS1(user)) {
      user = removePrefix(user);

      // we could do a sanity check here.  It might *not* be an SRS address,
      // unlikely though that is.  However, since we do not need to interpret
      // it, we don't really care if it's not an SRS address or not.
      // Malicious users get the garbage back that they sent

      // hash, srshost, srsuer
      Iterator<String> addressIter = Splitter.on(CharMatcher.anyOf(separators)).limit(3).split(user).iterator();

      addressIter.next(); // skip hash
      String srsHost = addressIter.next();
      String srsUser = addressIter.next();

      String hash = createHash(ImmutableList.of(srsHost, srsUser));

      return String.join(SRSSEP, SRSPrefix.SRS1, hash, srsHost, srsUser);
    } else if (isSRS0(user)) {
      // Remove tag, but preserve separator
      user = user.substring(SRSPrefix.SRS0.length());

      String hash = createHash(ImmutableList.of(host, user));

      return String.join(SRSSEP, SRSPrefix.SRS1, hash, host, user);
    }

    return super.compile(host, user);
  }
}
