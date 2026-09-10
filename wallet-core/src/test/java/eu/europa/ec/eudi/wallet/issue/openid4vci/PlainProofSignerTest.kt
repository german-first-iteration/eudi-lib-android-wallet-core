/*
 * Copyright (c) 2025 European Commission
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

package eu.europa.ec.eudi.wallet.issue.openid4vci

import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.openid4vci.JwtBindingKey
import eu.europa.ec.eudi.wallet.document.credential.ProofOfPossessionSigner
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.EcPublicKey
import org.multipaz.securearea.KeyInfo
import org.multipaz.securearea.KeyLockedException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class PlainProofSignerTest {

    private fun popSigner(
        alias: String,
        publicKey: EcPublicKey,
        onSign: (() -> Nothing)? = null,
    ): ProofOfPossessionSigner {
        val keyInfo = mockk<KeyInfo>()
        every { keyInfo.publicKey } returns publicKey
        every { keyInfo.algorithm } returns Algorithm.ESP256

        val signer = mockk<ProofOfPossessionSigner>()
        every { signer.keyAlias } returns alias
        every { signer.secureArea } returns mockk()
        coEvery { signer.getKeyInfo() } returns keyInfo
        if (onSign != null) {
            coEvery { signer.signPoP(any(), any()) } answers { onSign() }
        }
        return signer
    }

    private suspend fun keys(n: Int) =
        (0 until n).map { Crypto.createEcPrivateKey(EcCurve.P256).publicKey }

    @Test
    fun `produces one signer per binding key, each carrying its own public key as a jwk`() =
        runTest {
            val publicKeys = keys(3)
            val subject = PlainProofSigner(
                publicKeys.mapIndexed { i, key -> popSigner("alias-$i", key) }
            )

            val signers = subject.asSigners()

            assertEquals(3, signers.size, "one proof signer per credential-binding key")
            signers.forEachIndexed { i, signer ->
                val bindingKey = signer.acquire().publicMaterial
                // A plain JWT proof identifies the key by value in the `jwk` header, as opposed to
                // by index into a key attestation's attested_keys.
                assertIs<JwtBindingKey.Jwk>(bindingKey)
                assertEquals(
                    JWK.parse(publicKeys[i].toJwk().toString()),
                    bindingKey.jwk,
                    "signer $i must expose its own public key",
                )
            }
        }

    @Test
    fun `a locked key on any signer is recorded so the whole batch can be unlocked`() = runTest {
        val publicKeys = keys(3)
        val subject = PlainProofSigner(
            publicKeys.mapIndexed { i, key ->
                val onSign: (() -> Nothing)? =
                    if (i == 2) ({ throw KeyLockedException("locked") }) else null
                popSigner("alias-$i", key, onSign)
            }
        )
        assertNull(subject.keyLockedException)

        val lockedSigner = subject.asSigners()[2]
        assertFailsWith<KeyLockedException> {
            lockedSigner.acquire().function.sign(byteArrayOf(1, 2, 3))
        }

        assertNotNull(
            subject.keyLockedException,
            "the holder is shared, so SubmitRequest can raise one UserAuthRequiredException " +
                "covering every key alias in the batch",
        )
    }

    @Test
    fun `rejects an empty signer list`() {
        assertFailsWith<IllegalArgumentException> { PlainProofSigner(emptyList()) }
    }
}
