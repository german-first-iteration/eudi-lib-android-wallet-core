package eu.europa.ec.eudi.wallet.issue.openid4vci.dpop

import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.openid4vci.DPoPKeyAttestationSigner
import eu.europa.ec.eudi.openid4vci.Nonce
import eu.europa.ec.eudi.openid4vci.SignOperation
import eu.europa.ec.eudi.wallet.internal.d
import eu.europa.ec.eudi.wallet.logging.Logger
import org.multipaz.crypto.Algorithm
import org.multipaz.securearea.KeyInfo

/**
 * DPoP signer for PID issuance: it uses a provisional local key until the token
 * endpoint returns a DPoP nonce, then switches to an RWSCA key whose WTE is bound to that nonce.
 */
internal class KeyAttestedSecureAreaDpopSigner(
    private val provisionalSigner: SecureAreaDpopSigner,
    private val config: DPopConfig.KeyAttested,
    private val algorithms: List<Algorithm>,
    private val logger: Logger? = null,
) : DPopSigner, DPoPKeyAttestationSigner {

    private var attestedSigner: SecureAreaDpopSigner? = null

    val keyInfo: KeyInfo
        get() = activeSigner.keyInfo

    private val activeSigner: SecureAreaDpopSigner
        get() = attestedSigner ?: provisionalSigner

    override val javaAlgorithm: String
        get() = activeSigner.javaAlgorithm

    override suspend fun prepareKeyAttestation(nonce: Nonce) {
        if (attestedSigner != null) return

        val attestedConfig = DPopConfig.Custom(
            secureArea = config.secureArea,
            createKeySettingsBuilder = { supportedAlgorithms ->
                config.attestedCreateKeySettingsBuilder(supportedAlgorithms, nonce)
            },
            keyUnlockDataProvider = config.keyUnlockDataProvider,
        )
        attestedSigner = SecureAreaDpopSigner(attestedConfig, algorithms, logger).also {
            logger?.d(TAG, "Created nonce-bound DPoP key alias=${it.keyInfo.alias}")
        }
    }

    override suspend fun acquire(): SignOperation<JWK> = activeSigner.acquire()

    override suspend fun release(signOperation: SignOperation<JWK>?) {
        activeSigner.release(signOperation)
    }

    companion object {
        private const val TAG = "KeyAttestedDpopSigner"
    }
}
