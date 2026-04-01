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

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.booleans.shouldBeFalse
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotBeEmpty

class SRSTimestampTest :
    FunSpec({
      test("smoke") {
        val timestamp = SRSTimestamp.generate()

        timestamp.shouldNotBeEmpty()
        timestamp.length shouldBe 2
        SRSTimestamp.isInvalid(timestamp).shouldBeFalse()

        val now = System.currentTimeMillis()
        val notLong = 60L * 60 * 24 * 3 * 1000
        val ages = 60L * 60 * 24 * 50 * 1000

        // past timestamp not long ago should be ok
        SRSTimestamp.isInvalid(SRSTimestamp.generate(now - notLong)).shouldBeFalse()

        // very old timestamp is not ok
        SRSTimestamp.isInvalid(SRSTimestamp.generate(now - ages)).shouldBeTrue()

        // future timestamp fails
        SRSTimestamp.isInvalid(SRSTimestamp.generate(now + notLong)).shouldBeTrue()

        // far future timestamp fails
        SRSTimestamp.isInvalid(SRSTimestamp.generate(now + ages)).shouldBeTrue()
      }
    })
