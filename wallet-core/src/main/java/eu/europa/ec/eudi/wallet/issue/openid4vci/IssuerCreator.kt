/*
 * Copyright (c) 2024-2025 European Commission
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

import android.content.Context
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.AuthorizeIssuanceConfig
import eu.europa.ec.eudi.openid4vci.CIAuthorizationServerMetadata
import eu.europa.ec.eudi.openid4vci.ClientAuthentication
import eu.europa.ec.eudi.openid4vci.ClientAttestationJWT
import eu.europa.ec.eudi.openid4vci.PositiveDuration
import eu.europa.ec.eudi.openid4vci.ProvisionClientAttestation
import eu.europa.ec.eudi.openid4vci.CredentialConfigurationIdentifier
import eu.europa.ec.eudi.openid4vci.CredentialIssuerId
import eu.europa.ec.eudi.openid4vci.CredentialIssuerMetadata
import eu.europa.ec.eudi.openid4vci.CredentialOffer
import eu.europa.ec.eudi.openid4vci.Issuer
import eu.europa.ec.eudi.openid4vci.IssuerMetadataPolicy
import eu.europa.ec.eudi.openid4vci.OpenId4VCIConfig
import eu.europa.ec.eudi.openid4vci.DPoPUsage
import eu.europa.ec.eudi.openid4vci.HttpsUrl
import eu.europa.ec.eudi.openid4vci.JwsAlgorithm
import eu.europa.ec.eudi.openid4vci.ParUsage
import eu.europa.ec.eudi.openid4vci.ProofsConfig
import eu.europa.ec.eudi.openid4vci.RsaConfig
import eu.europa.ec.eudi.openid4vci.Signer
import eu.europa.ec.eudi.openid4vci.clientAttestationPOPJWSAlgs
import eu.europa.ec.eudi.wallet.document.format.DocumentFormat
import eu.europa.ec.eudi.wallet.document.format.MsoMdocFormat
import eu.europa.ec.eudi.wallet.document.format.SdJwtVcFormat
import eu.europa.ec.eudi.wallet.issue.openid4vci.CredentialConfigurationFilter.Companion.DocTypeFilter
import eu.europa.ec.eudi.wallet.issue.openid4vci.CredentialConfigurationFilter.Companion.VctFilter
import eu.europa.ec.eudi.wallet.issue.openid4vci.OpenId4VciManager.Companion.TAG
import eu.europa.ec.eudi.wallet.issue.openid4vci.dpop.DPopConfig
import eu.europa.ec.eudi.wallet.issue.openid4vci.dpop.DPopSigner
import eu.europa.ec.eudi.wallet.issue.openid4vci.dpop.KeyAttestedSecureAreaDpopSigner
import eu.europa.ec.eudi.wallet.issue.openid4vci.dpop.SecureAreaDpopSigner
import eu.europa.ec.eudi.wallet.internal.d
import eu.europa.ec.eudi.wallet.internal.e
import eu.europa.ec.eudi.wallet.internal.i
import eu.europa.ec.eudi.wallet.logging.Logger
import eu.europa.ec.eudi.wallet.provider.WalletInstanceAttestationProvider
import eu.europa.ec.eudi.wallet.provider.WalletKeyManager
import eu.europa.ec.eudi.wallet.registration.issuer.IssuerRegistrationResolver
import eu.europa.ec.eudi.wallet.registration.issuer.issuerRegistrationCertificatePolicy
import eu.europa.ec.eudi.wallet.registration.RegistrationCertificateResult
import io.ktor.client.HttpClient
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import org.multipaz.crypto.Algorithm
import java.net.URI
import java.time.Clock
import eu.europa.ec.eudi.openid4vci.DPoPConfig as VciDPoPConfig
import eu.europa.ec.eudi.openid4vci.ProvisionDPoPSigner as VciProvisionDPoPSigner

/**
 * An [Issuer] together with the outcome of validating the credential issuer's registration
 * certificate for this issuance.
 *
 * @property issuer the created issuer
 * @property issuerRegistration the registration outcome to present, or null when the certificate was
 * not evaluated and the caller is to evaluate it
 */
internal data class IssuerCreation(
    val issuer: Issuer,
    val issuerRegistration: RegistrationCertificateResult?,
)

/**
 * Creates an [Issuer] from the given [Offer].
 */
internal class IssuerCreator(
    private val context: Context,
    private val config: OpenId4VciManager.Config,
    private val ktorHttpClientFactory: () -> HttpClient,
    private val walletInstanceAttestationProvider: WalletInstanceAttestationProvider?,
    private val walletAttestationKeyManager: WalletKeyManager,
    private val logger: Logger?,
    private val issuerMetadataPolicy: IssuerMetadataPolicy = IssuerMetadataPolicy.IgnoreSigned,
    private val issuerRegistrationEnabled: Boolean = false,
    private val issuerRegistration: IssuerRegistrationResolver? = null,
) {

    internal var clientAttestationPopKeyId: String? = null
        private set

    private var dpopSigner: DPopSigner? = null

    internal val dpopKeyAlias: String?
        get() = when (val signer = dpopSigner) {
            is SecureAreaDpopSigner -> signer.keyInfo.alias
            is KeyAttestedSecureAreaDpopSigner -> signer.keyInfo.alias
            else -> null
        }

    internal lateinit var clientAuthentication: ClientAuthentication
        private set

    internal suspend fun currentDpopJkt(): String? {
        val alias = dpopKeyAlias ?: return null
        return dpopJktFromAlias(alias)
    }

    internal suspend fun dpopJktFromAlias(alias: String): String? {
        val secureArea = when (val cfg = config.dpopConfig) {
            DPopConfig.Disabled -> return null
            DPopConfig.Default -> DPopConfig.Default.make(context).secureArea
            is DPopConfig.Custom -> cfg.secureArea
            is DPopConfig.KeyAttested -> cfg.secureArea
        }
        val keyInfo = runCatching {
            secureArea.getKeyInfo(alias)
        }.getOrNull() ?: return null
        val jwk = JWK.parse(keyInfo.publicKey.toJwk().toString())
        return jwk.computeThumbprint().toString()
    }

    /**
     * Creates an [Issuer] from the given [Offer]. A registration outcome already carried by the offer
     * is reused, so the certificate is not evaluated again.
     * @param offer The [Offer].
     * @return The [Issuer] and the registration outcome.
     */
    suspend fun createIssuer(offer: Offer): IssuerCreation =
        doCreateIssuer(offer.credentialOffer, offer.issuerRegistration)

    suspend fun createIssuerWithAttestation(
        issuerUrl: String,
        attestationJWT: SignedJWT,
        walletWiaPopSigner: Signer<JWK>,
        credentialConfigurationIdentifiers: List<CredentialConfigurationIdentifier>,
        existingDpopKeyAlias: String? = null,
    ): Issuer {
        val authorizationServerMetadata = CredentialIssuerId(issuerUrl)
            .map { getIssuerMetadata(it).second.first() }
            .getOrThrow()

        return Issuer.makeWalletInitiated(
            config = config.toOpenId4VCIConfigWithAttestation(
                authorizationServerMetadata,
                attestationJWT,
                walletWiaPopSigner,
                existingDpopKeyAlias,
            ),
            credentialIssuerId = CredentialIssuerId(issuerUrl).getOrThrow(),
            credentialConfigurationIdentifiers = credentialConfigurationIdentifiers,
            httpClient = ktorHttpClientFactory()
        ).getOrThrow()
    }
    /**
     * Creates an [Issuer] from the given [CredentialConfigurationIdentifier]s.
     * @param issuerUrl The issuer URL.
     * @param credentialConfigurationIdentifiers The list of [CredentialConfigurationIdentifier]s.
     * @param existingDpopKeyAlias Optional alias of an existing DPoP key to reuse (for re-issuance).
     * @return The [Issuer] and the registration outcome.
     */
    suspend fun createIssuer(
        issuerUrl: String,
        credentialConfigurationIdentifiers: List<CredentialConfigurationIdentifier>,
        existingDpopKeyAlias: String? = null,
    ): IssuerCreation {

        val (issuerMetadata, authorizationServerMetadata) = CredentialIssuerId(issuerUrl)
            .map { getIssuerMetadata(it) }
            .getOrThrow()

        return doCreateIssuer(
            issuerMetadata, authorizationServerMetadata.first(), credentialConfigurationIdentifiers,
            existingDpopKeyAlias
        )
    }

    /**
     * Creates an [Issuer] from the given [DocumentFormat].
     * This method finds a suitable credential configuration based on the document format and creates an issuer.
     *
     * @param documentFormat The format of the document for which to create an issuer.
     * @return The [Issuer] supporting the given document format, and the registration outcome.
     * @throws IllegalStateException if no suitable configuration is found for the document format.
     */
    suspend fun createIssuer(issuerUrl: String, documentFormat: DocumentFormat): IssuerCreation {
        val formatFilter = when (documentFormat) {
            is MsoMdocFormat -> DocTypeFilter(documentFormat.docType)
            is SdJwtVcFormat -> VctFilter(documentFormat.vct)
        }
        val (issuerMetadata, authorizationServerMetadata) = CredentialIssuerId(issuerUrl)
            .map { getIssuerMetadata(it) }
            .getOrThrow()

        val configurationId = issuerMetadata.credentialConfigurationsSupported
            .filterValues { conf -> formatFilter(conf) }
            .firstNotNullOfOrNull { (confId, _) -> confId }
            ?: throw IllegalStateException("No suitable configuration found")

        return doCreateIssuer(issuerMetadata, authorizationServerMetadata.first(), listOf(configurationId))
    }


    private suspend fun getIssuerMetadata(credentialIssuerId: CredentialIssuerId): Pair<CredentialIssuerMetadata, List<CIAuthorizationServerMetadata>> {
        return ktorHttpClientFactory().use {
            Issuer.metaData(it, credentialIssuerId, issuerMetadataPolicy)
        }
    }


    private suspend fun doCreateIssuer(
        credentialOffer: CredentialOffer,
        resolvedRegistration: RegistrationCertificateResult? = null,
    ): IssuerCreation {
        var evaluatedRegistration: RegistrationCertificateResult? = null
        val issuer = Issuer.make(
            config = config.toOpenId4VCIConfig(
                credentialOffer.authorizationServerMetadata,
                credentialIssuerMetadata = credentialOffer.credentialIssuerMetadata,
                resolvedRegistration = resolvedRegistration,
                onRegistrationEvaluated = { evaluatedRegistration = it },
            ),
            credentialOffer = credentialOffer,
            httpClient = ktorHttpClientFactory()
        ).getOrThrow().first
        return IssuerCreation(issuer, resolvedRegistration ?: evaluatedRegistration)
    }

    private suspend fun doCreateIssuer(
        credentialIssuerMetadata: CredentialIssuerMetadata,
        authorizationServerMetadata: CIAuthorizationServerMetadata,
        credentialConfigurationIdentifiers: List<CredentialConfigurationIdentifier>,
        existingDpopKeyAlias: String? = null,
    ): IssuerCreation {
        return try {
            var evaluatedRegistration: RegistrationCertificateResult? = null
            val issuer = Issuer.makeWalletInitiated(
                config = config.toOpenId4VCIConfig(
                    authorizationServerMetadata,
                    existingDpopKeyAlias,
                    credentialIssuerMetadata,
                    onRegistrationEvaluated = { evaluatedRegistration = it },
                ),
                credentialIssuerId = credentialIssuerMetadata.credentialIssuerIdentifier,
                credentialConfigurationIdentifiers = credentialConfigurationIdentifiers,
                httpClient = ktorHttpClientFactory()
            ).getOrThrow().first
            IssuerCreation(issuer, evaluatedRegistration)
        } catch (e: Throwable) {
            logger?.e(TAG, "Failed to create wallet-initiated issuer", e)
            throw e
        }
    }

    private suspend fun CIAuthorizationServerMetadata.toClientAuthentication(): Result<ClientAuthentication> =
        runCatching {
            val issuerUrl = this.issuer.value
            when (val type = config.clientAuthenticationType) {
                is OpenId4VciManager.ClientAuthenticationType.None -> ClientAuthentication.None(type.clientId)
                is OpenId4VciManager.ClientAuthenticationType.AttestationBased -> {
                    val walletAttestationsProvider = checkNotNull(walletInstanceAttestationProvider) {
                        "WalletInstanceAttestationProvider is required for attestation-based client authentication"
                    }
                    val clientAttestationPOPJWSAlgs = clientAttestationPOPJWSAlgs
                        .takeUnless { it.isNullOrEmpty() }
                        ?: throw IllegalStateException(
                            "Client attestation based authentication is not supported by the authorization server at ${this.authorizationEndpointURI}"
                        )
                    val supportedAlgorithms = clientAttestationPOPJWSAlgs.map { a ->
                        Algorithm.fromJoseAlgorithmIdentifier(a.name)
                    }
                    walletAttestationKeyManager
                        .getOrCreateWalletAttestationKey(issuerUrl, supportedAlgorithms)
                        .map {
                            clientAttestationPopKeyId = it.keyInfo.alias
                            with(it) {
                                walletAttestationsProvider.toClientAuthentication(type.clientId).getOrThrow()
                            }
                        }.getOrThrow()
                }
            }
        }

    /**
     * Converts the [OpenId4VciManager.Config] to [OpenId4VCIConfig].
     * @receiver The [OpenId4VciManager.Config].
     * @return The [OpenId4VCIConfig].
     */
    private suspend fun OpenId4VciManager.Config.toOpenId4VCIConfig(
        authorizationServerMetadata: CIAuthorizationServerMetadata,
        existingDpopKeyAlias: String? = null,
        credentialIssuerMetadata: CredentialIssuerMetadata? = null,
        resolvedRegistration: RegistrationCertificateResult? = null,
        onRegistrationEvaluated: (RegistrationCertificateResult) -> Unit = {},
    ): OpenId4VCIConfig {
        val auth = authorizationServerMetadata.toClientAuthentication().getOrThrow()
        clientAuthentication = auth
        // Resolve DPoP usage
        val dPoPUsage = when (dpopConfig) {
            DPopConfig.Disabled -> DPoPUsage.Never

            DPopConfig.Default, is DPopConfig.Custom -> {
                val resolvedConfig = when (dpopConfig) {
                    DPopConfig.Default -> DPopConfig.Default.make(context)
                    is DPopConfig.Custom -> dpopConfig
                    else -> error("unreachable")
                }

                val signingAlg = resolvedConfig.secureArea.supportedAlgorithms
                    .firstOrNull { it.isSigning && it.joseAlgorithmIdentifier != null }
                    ?: throw IllegalStateException("No signing algorithm available for DPoP")

                val provisionDPoPSigner = if (existingDpopKeyAlias != null) {
                    // Re-issuance: reuse existing DPoP key bound to the access token
                    object : VciProvisionDPoPSigner {
                        override val popAlgorithm = JwsAlgorithm(signingAlg.joseAlgorithmIdentifier!!)
                        override suspend fun invoke(authorizationServer: HttpsUrl): Signer<JWK> {
                            return SecureAreaDpopSigner.fromExistingKey(
                                resolvedConfig, existingDpopKeyAlias, logger
                            ).also {
                                dpopSigner = it
                            }
                        }
                    }
                } else {
                    // Normal issuance: create new DPoP key
                    object : VciProvisionDPoPSigner {
                        override val popAlgorithm = JwsAlgorithm(signingAlg.joseAlgorithmIdentifier!!)
                        override suspend fun invoke(authorizationServer: HttpsUrl): Signer<JWK> {
                            return SecureAreaDpopSigner(
                                resolvedConfig, listOf(signingAlg), logger
                            ).also {
                                dpopSigner = it
                            }
                        }
                    }
                }

                DPoPUsage.IfSupported(VciDPoPConfig(provisionDPoPSigner))
            }

            is DPopConfig.KeyAttested -> {
                val cfg = dpopConfig as DPopConfig.KeyAttested
                val signingAlg = cfg.secureArea.supportedAlgorithms
                    .firstOrNull { it.isSigning && it.joseAlgorithmIdentifier != null }
                    ?: throw IllegalStateException("No signing algorithm available for DPoP")

                val provisionDPoPSigner = if (existingDpopKeyAlias != null) {
                    // Re-issuance: reuse the existing DPoP key bound to the access token
                    object : VciProvisionDPoPSigner {
                        override val popAlgorithm = JwsAlgorithm(signingAlg.joseAlgorithmIdentifier!!)
                        override suspend fun invoke(authorizationServer: HttpsUrl): Signer<JWK> {
                            val reuseConfig = DPopConfig.Custom(
                                secureArea = cfg.secureArea,
                                createKeySettingsBuilder = {
                                    error("Existing DPoP keys do not require create-key settings")
                                },
                                keyUnlockDataProvider = cfg.keyUnlockDataProvider,
                            )
                            return SecureAreaDpopSigner.fromExistingKey(
                                reuseConfig, existingDpopKeyAlias, logger
                            ).also {
                                dpopSigner = it
                            }
                        }
                    }
                } else {
                    // Normal issuance: provisional key until the token endpoint nonce is known,
                    // then a nonce-bound key-attested key.
                    object : VciProvisionDPoPSigner {
                        override val popAlgorithm = JwsAlgorithm(signingAlg.joseAlgorithmIdentifier!!)
                        override suspend fun invoke(authorizationServer: HttpsUrl): Signer<JWK> {
                            val provisionalConfig = DPopConfig.Default.make(context)
                            val provisionalSigner =
                                SecureAreaDpopSigner(provisionalConfig, listOf(signingAlg), logger)
                            return KeyAttestedSecureAreaDpopSigner(
                                provisionalSigner, cfg, listOf(signingAlg), logger
                            ).also {
                                dpopSigner = it
                            }
                        }
                    }
                }

                DPoPUsage.IfSupported(VciDPoPConfig(provisionDPoPSigner))
            }
        }

        if (issuerRegistrationEnabled && issuerMetadataPolicy !is IssuerMetadataPolicy.RequireSigned) {
            logger?.i(
                TAG,
                "issuer registration validation is enabled but signed issuer metadata is not " +
                    "configured (configureIssuerTrust { requireSignedMetadata() }); skipping it.",
            )
        }
        if (issuerRegistrationEnabled && issuerRegistration == null) {
            logger?.i(
                TAG,
                "issuer registration validation is enabled but no trust is available for the " +
                    "registration certificate signer chain (needs configureEtsiTrust); skipping it.",
            )
        }

        val registrationCertificatePolicy = issuerRegistration
            ?.takeIf { issuerMetadataPolicy is IssuerMetadataPolicy.RequireSigned }
            ?.let { resolver ->
                issuerRegistrationCertificatePolicy(
                    resolver = resolver,
                    resolvedRegistration = resolvedRegistration,
                    onEvaluated = onRegistrationEvaluated,
                    logger = logger,
                )
            }

        return OpenId4VCIConfig(
            clientAuthentication = auth,
            authFlowRedirectionURI = URI.create(authFlowRedirectionURI),
            encryptionSupportConfig = responseEncryptionConfig,
            supportedCredentialReusePolicies = supportedCredentialReusePolicies,
            dPoPUsage = dPoPUsage,
            parUsage = when (parUsage) {
                OpenId4VciManager.Config.ParUsage.IF_SUPPORTED -> ParUsage.IfSupported()
                OpenId4VciManager.Config.ParUsage.REQUIRED -> ParUsage.Required()
                OpenId4VciManager.Config.ParUsage.NEVER -> ParUsage.Never
                else -> ParUsage.IfSupported()
            },
            proofs = proofTypes.toProofsConfig(),
            issuerMetadataPolicy = if (issuerRegistrationEnabled) issuerMetadataPolicy else IssuerMetadataPolicy.IgnoreSigned,
            registrationCertificatePolicy = registrationCertificatePolicy,
        )
    }
    private suspend fun OpenId4VciManager.Config.toOpenId4VCIConfigWithAttestation(
        authorizationServerMetadata: CIAuthorizationServerMetadata,
        attestationJWT: SignedJWT,
        walletWiaPopSigner: Signer<JWK>,
        existingDpopKeyAlias: String? = null,
    ): OpenId4VCIConfig {
        // Build attestation-based client authentication from the externally supplied wallet
        // instance attestation JWT and its PoP signer, wrapped in the openid4vci 0.12.1
        // ProvisionClientAttestation abstraction (see WalletAttestationKey.toClientAuthentication
        // for the provider-driven equivalent used by the normal issuance path).
        val clientId = when (val type = clientAuthenticationType) {
            is OpenId4VciManager.ClientAuthenticationType.None -> type.clientId
            is OpenId4VciManager.ClientAuthenticationType.AttestationBased -> type.clientId
        }
        val attestationAlgorithm = JwsAlgorithm(attestationJWT.header.algorithm.name)
        val provisionClientAttestation = object : ProvisionClientAttestation {
            override val algorithm: JwsAlgorithm = attestationAlgorithm
            override val popAlgorithm: JwsAlgorithm = attestationAlgorithm

            override suspend fun invoke(
                authorizationServer: HttpsUrl,
                preferredClientStatusPeriod: PositiveDuration?,
            ): ProvisionClientAttestation.Provisioned =
                ProvisionClientAttestation.Provisioned(
                    clientAttestation = ClientAttestationJWT(attestationJWT),
                    popSigner = walletWiaPopSigner,
                )
        }
        val auth = ClientAuthentication.AttestationBased(
            id = clientId,
            provisionClientAttestation = provisionClientAttestation,
        )
        // Keep issuer-level state aligned with normal issuance path; downstream response
        // processing relies on this for metadata/re-issuance handling.
        clientAuthentication = auth

        val dPoPUsage = when (dpopConfig) {
            DPopConfig.Disabled -> DPoPUsage.Never

            DPopConfig.Default, is DPopConfig.Custom -> {
                val resolvedConfig = when (dpopConfig) {
                    DPopConfig.Default -> DPopConfig.Default.make(context)
                    is DPopConfig.Custom -> dpopConfig
                    else -> error("unreachable")
                }
                val signingAlg = resolvedConfig.secureArea.supportedAlgorithms
                    .firstOrNull { it.isSigning && it.joseAlgorithmIdentifier != null }
                    ?: throw IllegalStateException("No signing algorithm available for DPoP")
                val provisionDPoPSigner = if (existingDpopKeyAlias != null) {
                    object : VciProvisionDPoPSigner {
                        override val popAlgorithm = JwsAlgorithm(signingAlg.joseAlgorithmIdentifier!!)
                        override suspend fun invoke(authorizationServer: HttpsUrl): Signer<JWK> =
                            SecureAreaDpopSigner.fromExistingKey(resolvedConfig, existingDpopKeyAlias, logger)
                                .also { dpopSigner = it }
                    }
                } else {
                    object : VciProvisionDPoPSigner {
                        override val popAlgorithm = JwsAlgorithm(signingAlg.joseAlgorithmIdentifier!!)
                        override suspend fun invoke(authorizationServer: HttpsUrl): Signer<JWK> =
                            SecureAreaDpopSigner(resolvedConfig, listOf(signingAlg), logger)
                                .also { dpopSigner = it }
                    }
                }
                DPoPUsage.IfSupported(VciDPoPConfig(provisionDPoPSigner))
            }

            is DPopConfig.KeyAttested -> {
                val cfg = dpopConfig as DPopConfig.KeyAttested
                val signingAlg = cfg.secureArea.supportedAlgorithms
                    .firstOrNull { it.isSigning && it.joseAlgorithmIdentifier != null }
                    ?: throw IllegalStateException("No signing algorithm available for DPoP")
                val provisionDPoPSigner = if (existingDpopKeyAlias != null) {
                    object : VciProvisionDPoPSigner {
                        override val popAlgorithm = JwsAlgorithm(signingAlg.joseAlgorithmIdentifier!!)
                        override suspend fun invoke(authorizationServer: HttpsUrl): Signer<JWK> {
                            val reuseConfig = DPopConfig.Custom(
                                secureArea = cfg.secureArea,
                                createKeySettingsBuilder = {
                                    error("Existing DPoP keys do not require create-key settings")
                                },
                                keyUnlockDataProvider = cfg.keyUnlockDataProvider,
                            )
                            return SecureAreaDpopSigner.fromExistingKey(reuseConfig, existingDpopKeyAlias, logger)
                                .also { dpopSigner = it }
                        }
                    }
                } else {
                    object : VciProvisionDPoPSigner {
                        override val popAlgorithm = JwsAlgorithm(signingAlg.joseAlgorithmIdentifier!!)
                        override suspend fun invoke(authorizationServer: HttpsUrl): Signer<JWK> {
                            val provisionalConfig = DPopConfig.Default.make(context)
                            val provisionalSigner =
                                SecureAreaDpopSigner(provisionalConfig, listOf(signingAlg), logger)
                            return KeyAttestedSecureAreaDpopSigner(
                                provisionalSigner, cfg, listOf(signingAlg), logger
                            ).also { dpopSigner = it }
                        }
                    }
                }
                DPoPUsage.IfSupported(VciDPoPConfig(provisionDPoPSigner))
            }
        }

        return OpenId4VCIConfig(
            clientAuthentication = auth,
            authFlowRedirectionURI = URI.create(authFlowRedirectionURI),
            encryptionSupportConfig = responseEncryptionConfig,
            supportedCredentialReusePolicies = supportedCredentialReusePolicies,
            dPoPUsage = dPoPUsage,
            parUsage = when (parUsage) {
                OpenId4VciManager.Config.ParUsage.IF_SUPPORTED -> ParUsage.IfSupported()
                OpenId4VciManager.Config.ParUsage.REQUIRED -> ParUsage.Required()
                OpenId4VciManager.Config.ParUsage.NEVER -> ParUsage.Never
                else -> ParUsage.IfSupported()
            },
            proofs = proofTypes.toProofsConfig(),
        )
    }
}

private fun OpenId4VciManager.SupportedProofTypes.toProofsConfig(): ProofsConfig {
    return ProofsConfig(
        isNoProofSupported = isNoProofSupported,
        jwtProof = jwtProofAlgorithms?.let { algs ->
            ProofsConfig.SupportedJwtProof(algs.mapToJWSAlgorithms())
        },
        attestationProof = attestationProofAlgorithms?.let { algs ->
            ProofsConfig.SupportedAttestationProof(algs.mapToJWSAlgorithms())
        },
    )
}

private fun Set<Algorithm>.mapToJWSAlgorithms(): Set<JWSAlgorithm> =
    mapNotNull { it.joseAlgorithmIdentifier }
        .map { JWSAlgorithm.parse(it) }
        .toSet()
