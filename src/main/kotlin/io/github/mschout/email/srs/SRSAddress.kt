package io.github.mschout.email.srs

/**
 * Represents an SRS (Sender Rewriting Scheme) address, which is used to encode and decode email
 * addresses to support email forwarding while preserving SPF (Sender Policy Framework) compliance.
 *
 * @property prefix The SRS prefix indicating the type of the address (e.g., "SRS0" or "SRS1").
 * @property host The domain of the email address as transformed by the SRS process.
 * @property user The local part of the email address after SRS processing.
 * @property hash The hash used to validate the authenticity of the SRS address.
 */
data class SRSAddress(val prefix: String, val host: String, val user: String, val hash: String)
