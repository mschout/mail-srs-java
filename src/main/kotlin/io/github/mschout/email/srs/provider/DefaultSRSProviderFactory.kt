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
package io.github.mschout.email.srs.provider

/**
 * Factory for creating instances of `SRSProvider` with default configuration.
 *
 * This implementation is a singleton, accessible via the `instance` property. It uses default
 * parameter values specified in the `SRSProviderFactory` constructor to create `SRSProvider`
 * instances.
 *
 * This class is designed to produce providers compliant with the Sender Rewriting Scheme (SRS)
 * logic. The default configuration values for the factory include:
 * - Maximum age of the SRS timestamp (`maxAge`): 49
 * - Minimum length of the hash component (`hashMinLength`): 4
 * - Length of the hash component (`hashLength`): 4
 * - Separator used in SRS addresses (`separator`): `=`
 *
 * The singleton instance enforces consistent behavior across the application when creating SRS
 * providers.
 *
 * To use a custom configuration for creating an `SRSProvider`, refer to the `Builder` class of the
 * parent `SRSProviderFactory`.
 */
class DefaultSRSProviderFactory private constructor() :
    SRSProviderFactory(maxAge = 49, hashMinLength = 4, hashLength = 4, separator = "=") {

  companion object {

    /**
     * Singleton instance of `DefaultSRSProviderFactory`.
     *
     * This instance provides a default implementation of the `SRSProviderFactory` class with
     * preconfigured parameters:
     * - Maximum age of the SRS timestamp: 49
     * - Minimum length of the hash component: 4
     * - Length of the hash component: 4
     * - Separator used in SRS addresses: `=`
     *
     * The factory is used to create instances of `SRSProvider` with default settings, ensuring
     * consistent behavior across the application.
     */
    @JvmStatic val instance = DefaultSRSProviderFactory()
  }
}
