package net.oneplus.androidkeystore

import android.content.Context
import android.hardware.fingerprint.FingerprintManager
import android.os.Bundle
import android.os.CancellationSignal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.support.design.widget.Snackbar
import android.support.v7.app.AppCompatActivity
import android.util.Log
import android.view.Menu
import android.view.MenuItem
import android.widget.Toast
import kotlinx.android.synthetic.main.activity_main.*
import kotlinx.android.synthetic.main.content_main.*
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec

class MainActivity : AppCompatActivity() {
    companion object {
        const val ANDROID_KEY_STORE: String = "AndroidKeyStore"
        const val TRANSFORMATION: String = "AES/GCM/NoPadding"
        const val KEY_ALIAS: String = "alias"
    }

    private var iv: ByteArray = ByteArray(0)
    private var fingerprintManager: FingerprintManager? = null
    private var cancellationSignal: CancellationSignal? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        setSupportActionBar(toolbar)

        fab.setOnClickListener { view ->
            Snackbar.make(view, "Replace with your own action", Snackbar.LENGTH_LONG)
                    .setAction("Action", null).show()
        }

        btn_enc.setOnClickListener {
            enc(text_to_enc.text.toString())
        }
        btn_dec.setOnClickListener {
            if (iv.isEmpty()) {
                Toast.makeText(this, "Please encrypt first", Toast.LENGTH_SHORT).show()
            } else {
                dec(text.text.toString().hexToByteArray(), iv)
            }
        }

        fingerprintManager = getSystemService(Context.FINGERPRINT_SERVICE) as FingerprintManager
    }

//    private fun checkFingerprint(cipher: Cipher, callback: FingerprintManager.AuthenticationCallback) {
//        if (!fingerprintManager!!.isHardwareDetected) {
//            Toast.makeText(this, "Fingerprint HW not detected", Toast.LENGTH_SHORT).show()
//            return
//        }
//        if (!fingerprintManager!!.hasEnrolledFingerprints()) {
//            Toast.makeText(this, "No fingerprint enrolled", Toast.LENGTH_SHORT).show()
//            return
//        }
//        cancellationSignal = CancellationSignal()
//        fingerprintManager!!.authenticate(FingerprintManager.CryptoObject(cipher), cancellationSignal, 0, callback, null)
//    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        // Inflate the menu; this adds items to the action bar if it is present.
        menuInflater.inflate(R.menu.menu_main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        return when (item.itemId) {
            R.id.action_settings -> true
            else -> super.onOptionsItemSelected(item)
        }
    }

    private fun enc(textToEncrypt: String) {
//        if (!fingerprintManager!!.isHardwareDetected) {
//            Toast.makeText(this, "Fingerprint HW not detected", Toast.LENGTH_SHORT).show()
//            return
//        }
//        if (!fingerprintManager!!.hasEnrolledFingerprints()) {
//            Toast.makeText(this, "No fingerprint enrolled", Toast.LENGTH_SHORT).show()
//            return
//        }

        val keyGenParameterSpec = KeyGenParameterSpec.Builder(KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
//                .setUserAuthenticationRequired(true)
                .build()

        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE)
        keyGenerator.init(keyGenParameterSpec)
        val secretKey = keyGenerator.generateKey()

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        iv = cipher.iv

        val cipherText = cipher.doFinal(textToEncrypt.toByteArray()).toHex()
        Log.d("Martin", "iv: ${iv.toHex()}, cipherText: $cipherText")

//        val dialog = AlertDialog.Builder(this).create()
//        dialog.setView(View.inflate(this, R.layout.fingerprint_dialog_content, null))
//        dialog.show()
//
//        checkFingerprint(cipher, object : FingerprintManager.AuthenticationCallback() {
//            override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
//                Log.i("Martin", "onAuthenticationError: err: $errString")
//            }
//
//            override fun onAuthenticationSucceeded(result: FingerprintManager.AuthenticationResult?) {
//                Log.i("Martin", "onAuthenticationSucceeded")
//                dialog.dismiss()
//                text.text = cipher.doFinal(textToEncrypt.toByteArray()).toHex()
//            }
//
//            override fun onAuthenticationFailed() {
//                Log.i("Martin", "onAuthenticationFailed")
//            }
//        })

        text.text = cipherText

//        val factory = SecretKeyFactory.getInstance(secretKey.algorithm, "AndroidKeyStore")
//        val keyInfo: KeyInfo
//        try {
//            keyInfo = factory.getKeySpec(secretKey, KeyInfo::class.java) as KeyInfo
//            Log.d("Martin", "keyInfo.isInsideSecureHardware: ${keyInfo.isInsideSecureHardware}")
//        } catch (e: InvalidKeySpecException) {
//            // Not an Android KeyStore key.
//        }
    }

    private fun dec(encryptedData: ByteArray, encryptedIv: ByteArray) {
//        if (!fingerprintManager!!.isHardwareDetected) {
//            Toast.makeText(this, "Fingerprint HW not detected", Toast.LENGTH_SHORT).show()
//            return
//        }
//        if (!fingerprintManager!!.hasEnrolledFingerprints()) {
//            Toast.makeText(this, "No fingerprint enrolled", Toast.LENGTH_SHORT).show()
//            return
//        }

        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        val secretKeyEntry = keyStore.getEntry(KEY_ALIAS, null) as KeyStore.SecretKeyEntry
        val secretKey = secretKeyEntry.secretKey
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, encryptedIv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)

//        val dialog = AlertDialog.Builder(this).create()
//        dialog.setView(View.inflate(this, R.layout.fingerprint_dialog_content, null))
//        dialog.show()
//
//        checkFingerprint(cipher, object : FingerprintManager.AuthenticationCallback() {
//            override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
//                Log.i("Martin", "onAuthenticationError: err: $errString")
//            }
//
//            override fun onAuthenticationSucceeded(result: FingerprintManager.AuthenticationResult?) {
//                Log.i("Martin", "onAuthenticationSucceeded")
//                dialog.dismiss()
//                text.text = String(cipher.doFinal(encryptedData))
//            }
//
//            override fun onAuthenticationFailed() {
//                Log.i("Martin", "onAuthenticationFailed")
//            }
//        })

        text.text = String(cipher.doFinal(encryptedData))
    }
}
