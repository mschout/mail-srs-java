/*
 * Copyright 2026 Michael Schout
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
