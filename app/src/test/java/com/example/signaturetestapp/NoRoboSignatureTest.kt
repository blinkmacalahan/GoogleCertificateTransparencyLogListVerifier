package com.example.signaturetestapp

import org.junit.*
import java.io.IOException
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.SignatureException
import java.security.spec.InvalidKeySpecException

class NoRoboSignatureTest {
    private lateinit var signatureBytes: ByteArray

    private lateinit var keyBytes: ByteArray

    private lateinit var jsonBytes: ByteArray

    /**
     * Unable to use @BeforeClass due to context not being available yet:
     * java.lang.IllegalStateException: No instrumentation registered! Must run under a registering instrumentation.
     */
    @Before
    fun setup() {
        try {
            signatureBytes = MainJavaActivity.toByteArray(javaClass.getResourceAsStream("log_list.sig"))
            keyBytes = MainJavaActivity.loadPEM(javaClass.getResourceAsStream("log_list_pubkey.pem"))
            jsonBytes = MainJavaActivity.toByteArray(javaClass.getResourceAsStream("log_list.json"))
        } catch (e: IOException) {
            e.printStackTrace()
        }
    }

    @Test
    @Throws(
        InvalidKeySpecException::class,
        NoSuchAlgorithmException::class,
        InvalidKeyException::class,
        SignatureException::class
    )
    fun verifyLogListWithUppercase() {
        Assert.assertTrue(
            "Verify with " + MainJavaActivity.UPPERCASE_WITH_SHA256_WITH_RSA,
            MainJavaActivity.isGoogleLogListVerified(
                MainJavaActivity.UPPERCASE_WITH_SHA256_WITH_RSA,
                signatureBytes,
                keyBytes,
                jsonBytes
            )
        )
    }

    @Test
    @Throws(
        InvalidKeySpecException::class,
        NoSuchAlgorithmException::class,
        InvalidKeyException::class,
        SignatureException::class
    )
    fun verifyLogListWithLowercase() {
        Assert.assertTrue(
            "Verify with " + MainJavaActivity.LOWERCASE_SHA256_WITH_RSA,
            MainJavaActivity.isGoogleLogListVerified(
                MainJavaActivity.LOWERCASE_SHA256_WITH_RSA,
                signatureBytes,
                keyBytes,
                jsonBytes
            )
        )
    }
}