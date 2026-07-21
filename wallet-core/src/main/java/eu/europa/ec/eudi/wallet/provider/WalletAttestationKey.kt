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

package eu.europa.ec.eudi.wallet.provider

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.ClientAttestationJWT
import eu.europa.ec.eudi.openid4vci.ClientAuthentication
import eu.europa.ec.eudi.openid4vci.HttpsUrl
import eu.europa.ec.eudi.openid4vci.JwsAlgorithm
import eu.europa.ec.eudi.openid4vci.PositiveDuration
import eu.europa.ec.eudi.openid4vci.ProvisionClientAttestation
import eu.europa.ec.eudi.openid4vci.SignOperation
import eu.europa.ec.eudi.openid4vci.Signer
import eu.europa.ec.eudi.wallet.issue.openid4vci.javaAlgorithm
import org.multipaz.securearea.KeyInfo

open class WalletAttestationKey(
    val keyInfo: KeyInfo,
    val signFunction: suspend (ByteArray) -> ByteArray,
) {

    /**
     * @param clientId the `client_id` to authenticate with, or null to derive it from the client
     *   attestation. Pass a value only to keep using one from an earlier issuance (see
     *   [eu.europa.ec.eudi.wallet.issue.openid4vci.DeferredContext]); fresh issuance derives it.
     */
    suspend fun WalletInstanceAttestationProvider.toClientAuthentication(
        clientId: String? = null,
    ): Result<ClientAuthentication.AttestationBased> =
        runCatching {
            val joseAlgId = checkNotNull(keyInfo.algorithm.joseAlgorithmIdentifier) {
                "JOSE algorithm identifier not found for wallet attestation key"
            }
            val jwsAlgorithm = JwsAlgorithm(joseAlgId)
            val javaAlg = checkNotNull(keyInfo.algorithm.javaAlgorithm) {
                "Java algorithm not found for wallet attestation key"
            }

            val walletAttestationsProvider = this@toClientAuthentication
            val walletAttestationKey = this@WalletAttestationKey

            // The request `client_id` must equal the client attestation's `sub`, so it is derived
            // from the attestation rather than taken from ClientAuthenticationType.AttestationBased
            // (whose configured value is the issuer URL for our wallet). Fetch the attestation up
            // front for the subject and hand that same one to the first provisioning call, so the
            // wallet provider is not asked twice for it.
            var pendingAttestation: String? = null
            val resolvedClientId = clientId ?: run {
                val attestation = walletAttestationsProvider
                    .getWalletAttestation(walletAttestationKey.keyInfo)
                    .getOrThrow()
                pendingAttestation = attestation
                requireNotNull(SignedJWT.parse(attestation).jwtClaimsSet.subject) {
                    "Client attestation JWT is missing the 'sub' (client id) claim"
                }
            }

            val provisionClientAttestation = object : ProvisionClientAttestation {
                override val algorithm: JwsAlgorithm = jwsAlgorithm
                override val popAlgorithm: JwsAlgorithm = jwsAlgorithm

                override suspend fun invoke(
                    authorizationServer: HttpsUrl,
                    preferredClientStatusPeriod: PositiveDuration?,
                ): ProvisionClientAttestation.Provisioned {
                    val jwtString = pendingAttestation?.also { pendingAttestation = null }
                        ?: walletAttestationsProvider
                            .getWalletAttestation(walletAttestationKey.keyInfo)
                            .getOrThrow()
                    val clientAttestation = ClientAttestationJWT(jwtString)
                    val popSigner = object : Signer<JWK> {
                        override val javaAlgorithm: String = javaAlg

                        override suspend fun acquire(): SignOperation<JWK> {
                            return SignOperation(
                                function = { walletAttestationKey.signFunction(it) },
                                publicMaterial = JWK.parse(
                                    walletAttestationKey.keyInfo.publicKey.toJwk().toString()
                                )
                            )
                        }

                        override suspend fun release(signOperation: SignOperation<JWK>?) {
                            // nothing to release
                        }
                    }
                    return ProvisionClientAttestation.Provisioned(clientAttestation, popSigner)
                }
            }

            ClientAuthentication.AttestationBased(
                id = resolvedClientId,
                provisionClientAttestation = provisionClientAttestation,
            )
        }
}
