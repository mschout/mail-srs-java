package io.github.mschout.email.srs.provider

import io.github.mschout.email.srs.SRSAddress
import java.security.InvalidKeyException

/**
 * Interface for an SRS (Sender Rewriting Scheme) provider. SRS is used to rewrite the envelope
 * sender of an email to support email forwarding while maintaining SPF (Sender Policy Framework)
 * compliance.
 *
 * Implementations of this interface handle the generation and parsing of SRS addresses, as well as
 * validation functions for SRS address types.
 */
interface SRSProvider {

  fun isSRS0(address: String): Boolean

  fun isSRS1(address: String): Boolean

  @Throws(InvalidKeyException::class) fun compile(host: String, user: String): String

  fun parse(srsAddress: String): SRSAddress

  val secret: String

  val separator: String
}
