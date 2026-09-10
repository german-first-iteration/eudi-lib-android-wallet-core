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
import eu.europa.ec.eudi.openid4vci.SignOperation
import eu.europa.ec.eudi.openid4vci.Signer
import eu.europa.ec.eudi.wallet.document.credential.ProofOfPossessionSigner
import kotlinx.coroutines.runBlocking
import org.multipaz.securearea.KeyLockedException
import org.multipaz.securearea.KeyUnlockData

/**
 * Produces one plain JWT proof signer per credential-binding key, i.e. proofs whose JOSE header
 * carries the public key as `jwk` and no key attestation.
 *
 * FORK ADDITION -- replaces the `BatchProofSigner` that wallet-core had up to v0.28.1 and that was
 * dropped when openid4vci v0.12.0 removed plain JWT proofs. It is used only for issuers that
 * advertise a `jwt` proof type without `key_attestations_required`; see [SubmitRequest].
 *
 * All signers share this instance's [keyLockedException] so that a locked key surfaced by any of
 * them can be turned into a single [UserAuthRequiredException] covering every key in the batch.
 */
class PlainProofSigner(
    val signers: List<ProofOfPossessionSigner>,
    private val keyUnlockData: Map<String, KeyUnlockData?>? = null,
) {
    init {
        require(signers.isNotEmpty()) { "At least one proof of possession signer is required" }
    }

    val algorithm by lazy {
        runBlocking { signers.first().getKeyInfo().algorithm }
    }

    private val javaAlgorithm: String = algorithm.javaAlgorithm
        ?: throw IllegalArgumentException("Unsupported algorithm: $algorithm")

    var keyLockedException: KeyLockedException? = null
        private set

    fun asSigners(): List<Signer<JwtBindingKey>> = signers.map { SingleKeySigner(it) }

    private inner class SingleKeySigner(
        private val signer: ProofOfPossessionSigner,
    ) : Signer<JwtBindingKey> {

        override val javaAlgorithm: String = this@PlainProofSigner.javaAlgorithm

        override suspend fun acquire(): SignOperation<JwtBindingKey> {
            val jwk = JWK.parse(signer.getKeyInfo().publicKey.toJwk().toString())
            val keyUnlockDataForSigner = keyUnlockData?.get(signer.keyAlias)
            return SignOperation(
                function = { input ->
                    try {
                        signer.signPoP(input, keyUnlockDataForSigner).toDerEncoded()
                    } catch (e: KeyLockedException) {
                        keyLockedException = e
                        throw e
                    }
                },
                publicMaterial = JwtBindingKey.Jwk(jwk),
            )
        }

        override suspend fun release(signOperation: SignOperation<JwtBindingKey>?) {
            // nothing to release
        }
    }
}
