import type { RuleCase } from "./types.js";

export const cases: RuleCase[] = [
  // ---------------------------------------------------------------------------
  // AndroidManifest.xml — checkManifests()
  // ---------------------------------------------------------------------------
  {
    ruleId: "ANDROID_DEBUGGABLE",
    check: "mobile-android",
    positive: {
      file: "app/src/main/AndroidManifest.xml",
      content: `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
    <application
        android:label="ExampleApp"
        android:debuggable="true">
        <activity android:name=".MainActivity" android:exported="true" />
    </application>
</manifest>
`
    },
    negative: {
      file: "app/src/main/AndroidManifest.xml",
      content: `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
    <application android:label="ExampleApp">
        <activity android:name=".MainActivity" android:exported="true" />
    </application>
</manifest>
`
    },
    note: "Negative simply omits android:debuggable from the source manifest, relying on the AGP build-variant merger to set it per build type (the standard, correct release setup) instead of hardcoding true and hoping a downstream step overrides it."
  },
  {
    ruleId: "ANDROID_CLEARTEXT",
    check: "mobile-android",
    positive: {
      file: "app/src/main/AndroidManifest.xml",
      content: `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
    <application android:label="ExampleApp" android:usesCleartextTraffic="true">
        <activity android:name=".MainActivity" android:exported="true" />
    </application>
</manifest>
`
    },
    negative: {
      file: "app/src/main/AndroidManifest.xml",
      content: `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
    <application
        android:label="ExampleApp"
        android:usesCleartextTraffic="false"
        android:networkSecurityConfig="@xml/network_security_config">
        <activity android:name=".MainActivity" android:exported="true" />
    </application>
</manifest>
`
    },
    note: "Negative explicitly sets usesCleartextTraffic=false and wires a network security config, the exact remediation, rather than merely deleting the attribute."
  },
  {
    ruleId: "ANDROID_BACKUP_ALLOWED",
    check: "mobile-android",
    positive: {
      file: "app/src/main/AndroidManifest.xml",
      content: `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
    <application android:label="ExampleApp" android:allowBackup="true">
        <activity android:name=".MainActivity" android:exported="true" />
    </application>
</manifest>
`
    },
    negative: {
      file: "app/src/main/AndroidManifest.xml",
      content: `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
    <application android:label="ExampleApp" android:allowBackup="false">
        <activity android:name=".MainActivity" android:exported="true" />
    </application>
</manifest>
`
    },
    note: "Negative sets allowBackup=false, the direct fix the rule's own requiredActions recommend as the default-safe choice."
  },
  {
    ruleId: "ANDROID_EXPORTED_NO_PERMISSION",
    check: "mobile-android",
    positive: {
      file: "app/src/main/AndroidManifest.xml",
      content: `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
    <application android:label="ExampleApp">
        <activity android:name=".ShareActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.SEND" />
                <category android:name="android.intent.category.DEFAULT" />
            </intent-filter>
        </activity>
    </application>
</manifest>
`
    },
    negative: {
      file: "app/src/main/AndroidManifest.xml",
      content: `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
    <application android:label="ExampleApp">
        <activity
            android:name=".ShareActivity"
            android:exported="true"
            android:permission="com.example.app.permission.SHARE_ACTIVITY">
            <intent-filter>
                <action android:name="android.intent.action.SEND" />
                <category android:name="android.intent.category.DEFAULT" />
            </intent-filter>
        </activity>
    </application>
</manifest>
`
    },
    note: "Negative adds android:permission directly on the exported activity's opening tag (a signature-level custom permission), exactly what requiredActions calls for, rather than removing exported=true."
  },
  {
    ruleId: "ANDROID_DEEPLINK_NO_VERIFY",
    check: "mobile-android",
    positive: {
      file: "app/src/main/AndroidManifest.xml",
      content: `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
    <application android:label="ExampleApp">
        <activity android:name=".DeepLinkActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="https" android:host="example.com" />
            </intent-filter>
        </activity>
    </application>
</manifest>
`
    },
    negative: {
      file: "app/src/main/AndroidManifest.xml",
      content: `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
    <application android:label="ExampleApp">
        <activity android:name=".DeepLinkActivity" android:exported="true">
            <intent-filter android:autoVerify="true">
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="https" android:host="example.com" />
            </intent-filter>
        </activity>
    </application>
</manifest>
`
    },
    note: "Negative adds android:autoVerify=\"true\" on the same intent-filter carrying the https data element, enabling Android App Links verification instead of leaving the https intent-filter unverified."
  },
  {
    ruleId: "ANDROID_NSC_MISSING",
    check: "mobile-android",
    positive: {
      file: "app/src/main/AndroidManifest.xml",
      content: `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
    <application android:label="ExampleApp">
        <activity android:name=".MainActivity" android:exported="true" />
    </application>
</manifest>
`
    },
    negative: {
      file: "app/src/main/AndroidManifest.xml",
      content: `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
    <application
        android:label="ExampleApp"
        android:networkSecurityConfig="@xml/network_security_config">
        <activity android:name=".MainActivity" android:exported="true" />
    </application>
</manifest>
`
    },
    note: "Negative references android:networkSecurityConfig on <application>, the exact attribute the rule tests for the absence of."
  },
  {
    ruleId: "ANDROID_CONTENT_PROVIDER_NO_PERMISSIONS",
    check: "mobile-android",
    positive: {
      file: "app/src/main/AndroidManifest.xml",
      content: `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
    <application android:label="ExampleApp">
        <provider
            android:name=".DataProvider"
            android:authorities="com.example.app.provider"
            android:exported="true" />
    </application>
</manifest>
`
    },
    negative: {
      file: "app/src/main/AndroidManifest.xml",
      content: `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
    <application android:label="ExampleApp">
        <provider
            android:name=".DataProvider"
            android:authorities="com.example.app.provider"
            android:exported="true"
            android:readPermission="com.example.app.permission.READ_DATA"
            android:writePermission="com.example.app.permission.WRITE_DATA" />
    </application>
</manifest>
`
    },
    note: "Negative adds android:readPermission and android:writePermission inside the same <provider> opening tag, which defeats the rule's negative lookaheads for those exact attributes."
  },
  {
    ruleId: "ANDROID_WILDCARD_MIME_INTENT_FILTER",
    check: "mobile-android",
    positive: {
      file: "app/src/main/AndroidManifest.xml",
      content: `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
    <application android:label="ExampleApp">
        <activity android:name=".FileViewerActivity">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <data android:mimeType="*/*" />
            </intent-filter>
        </activity>
    </application>
</manifest>
`
    },
    negative: {
      file: "app/src/main/AndroidManifest.xml",
      content: `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
    <application android:label="ExampleApp">
        <activity android:name=".FileViewerActivity">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <data android:mimeType="application/pdf" />
            </intent-filter>
        </activity>
    </application>
</manifest>
`
    },
    note: "Negative declares the specific MIME type the component actually handles (application/pdf) instead of the wildcard */*, exactly as requiredActions instructs."
  },

  // ---------------------------------------------------------------------------
  // network_security_config.xml — checkNetworkSecurityConfig()
  // ---------------------------------------------------------------------------
  {
    ruleId: "ANDROID_NSC_WEAK",
    check: "mobile-android",
    positive: {
      file: "app/src/main/res/xml/network_security_config.xml",
      content: `<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
`
    },
    negative: {
      file: "app/src/main/res/xml/network_security_config.xml",
      content: `<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    <pin-set>
        <pin digest="SHA-256">7HIpactkIAq2Y49orFOOQKurWxmmSFZhBCoQYcRhJ3Y=</pin>
        <pin digest="SHA-256">fwza0LRMXouZHRC8Ei+4PyuldPDcf3UKgO/04cDM1oE=</pin>
    </pin-set>
</network-security-config>
`
    },
    note: "Negative drops the <certificates src=\"user\"> trust anchor entirely (system-only) and adds a <pin-set>, matching every remediation bullet — the positive's user-CA trust anchor is exactly what makes it MITM-able and is what the rule's hasUserCerts check looks for."
  },

  // ---------------------------------------------------------------------------
  // Kotlin/Java source — checkSourceFiles()
  // ---------------------------------------------------------------------------
  {
    ruleId: "ANDROID_WEBVIEW_JS_INTERFACE",
    check: "mobile-android",
    positive: {
      file: "app/src/main/java/com/example/app/MainActivity.kt",
      content: `package com.example.app

import android.os.Bundle
import android.webkit.JavascriptInterface
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val webView = findViewById<android.webkit.WebView>(R.id.webview)
        webView.settings.javaScriptEnabled = true
        webView.addJavascriptInterface(WebAppInterface(this), "Android")
        webView.loadUrl("https://example.com")
    }

    class WebAppInterface(private val context: android.content.Context) {
        @JavascriptInterface
        fun showToast(message: String) {
            android.widget.Toast.makeText(context, message, android.widget.Toast.LENGTH_SHORT).show()
        }
    }
}
`
    },
    negative: {
      file: "app/src/main/java/com/example/app/MainActivity.kt",
      content: `package com.example.app

import android.net.Uri
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.webkit.WebMessageListenerCompat
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val webView = findViewById<android.webkit.WebView>(R.id.webview)
        webView.settings.javaScriptEnabled = true

        if (WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {
            WebViewCompat.addWebMessageListener(
                webView,
                "nativeBridge",
                setOf("https://example.com"),
                WebMessageListenerCompat { _, message, sourceOrigin, _, _ ->
                    handleBridgeMessage(message.data, sourceOrigin)
                }
            )
        }
        webView.loadUrl("https://example.com")
    }

    private fun handleBridgeMessage(data: String?, sourceOrigin: Uri) {
        // sourceOrigin is validated against the explicit allowlist passed to addWebMessageListener
    }
}
`
    },
    note: "The rule fires unconditionally on the literal string addJavascriptInterface with no suppression path, so the only genuine fix is not using that API at all. Negative uses AndroidX WebViewCompat.addWebMessageListener scoped to an explicit origin allowlist, the modern replacement bridge API."
  },
  {
    ruleId: "ANDROID_WEBVIEW_JS_ENABLED",
    check: "mobile-android",
    positive: {
      file: "app/src/main/java/com/example/app/WebViewActivity.kt",
      content: `package com.example.app

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity

class WebViewActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val webView = findViewById<android.webkit.WebView>(R.id.webview)
        val settings = webView.settings
        settings.setJavaScriptEnabled(true)
        settings.domStorageEnabled = true
        webView.loadUrl("https://example.com")
    }
}
`
    },
    negative: {
      file: "app/src/main/java/com/example/app/WebViewActivity.kt",
      content: `package com.example.app

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity

class WebViewActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val webView = findViewById<android.webkit.WebView>(R.id.webview)
        val settings = webView.settings
        settings.setJavaScriptEnabled(true)
        settings.setSaveFormData(false)
        settings.setSavePassword(false)
        settings.setAllowFileAccess(false)
        webView.loadUrl("https://example.com")
    }
}
`
    },
    note: "Negative calls both setSaveFormData(false) and setSavePassword(false) alongside setJavaScriptEnabled(true), the exact pair the rule checks for before suppressing, per requiredActions."
  },
  {
    ruleId: "ANDROID_SHARED_PREFS_SENSITIVE",
    check: "mobile-android",
    positive: {
      file: "app/src/main/java/com/example/app/AuthPreferences.kt",
      content: `package com.example.app

import android.content.Context

class AuthPreferences(context: Context) {
    private val prefs = context.getSharedPreferences("app_prefs", Context.MODE_PRIVATE)

    fun saveAuthToken(token: String) {
        val editor = prefs.edit()
        editor.putString("auth_token", token)
        editor.apply()
    }
}
`
    },
    negative: {
      file: "app/src/main/java/com/example/app/AuthPreferences.kt",
      content: `package com.example.app

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

class AuthPreferences(context: Context) {
    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val encryptedPrefs = EncryptedSharedPreferences.create(
        context,
        "secure_auth_prefs",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    fun saveAuthToken(token: String) {
        val editor = encryptedPrefs.edit()
        editor.putString("auth_token", token)
        editor.apply()
    }
}
`
    },
    note: "Negative never calls plain getSharedPreferences/defaultSharedPreferences at all — it stores the same auth_token value through EncryptedSharedPreferences (Jetpack Security) end to end, which is the rule's own required fix, not a renamed call."
  },
  {
    ruleId: "ANDROID_LOGCAT_SENSITIVE",
    check: "mobile-android",
    positive: {
      file: "app/src/main/java/com/example/app/AuthRepository.kt",
      content: `package com.example.app

import android.util.Log

class AuthRepository {
    fun login(username: String, password: String): String {
        val authToken = performLogin(username, password)
        Log.d("AuthDebug", "User login token: $authToken, password: $password")
        return authToken
    }

    private fun performLogin(username: String, password: String): String = "token-123"
}
`
    },
    negative: {
      file: "app/src/main/java/com/example/app/AuthRepository.kt",
      content: `package com.example.app

import android.util.Log

class AuthRepository {
    fun login(username: String, userId: String): String {
        val authResult = performLogin(username, userId)
        Log.d("AuthDebug", "Login attempt for user id: $userId, result: $authResult")
        return authResult
    }

    private fun performLogin(username: String, userId: String): String = "ok"
}
`
    },
    note: "Negative's Log.d call carries only a user id and a non-secret result string — no password/token/secret/apikey/credential substring appears anywhere near a Log.[dwive] call, so the rule's keyword-in-log-line test has nothing to match."
  },
  {
    ruleId: "ANDROID_HARDCODED_SECRET",
    check: "mobile-android",
    positive: {
      file: "app/src/main/java/com/example/app/ApiConfig.kt",
      content: `package com.example.app

object ApiConfig {
    const val apiKey = "AIzaSyD9x7ZqL3mK8vB2nR5tY6wU1oP4sC0eFgH"
    const val baseUrl = "https://api.example.com"
}
`
    },
    negative: {
      file: "app/src/main/java/com/example/app/ApiConfig.kt",
      content: `package com.example.app

object ApiConfig {
    val apiKey: String = BuildConfig.MAPS_API_KEY
    const val baseUrl = "https://api.example.com"
}
`
    },
    note: "Negative loads the key from BuildConfig (injected at build time from a non-committed local.properties/CI secret), so there is no quoted literal following apiKey =, which is what the rule's regex requires to fire."
  },
  {
    ruleId: "ANDROID_SQL_RAW_QUERY",
    check: "mobile-android",
    positive: {
      file: "app/src/main/java/com/example/app/UserDao.kt",
      content: `package com.example.app

import android.database.sqlite.SQLiteDatabase

class UserDao(private val db: SQLiteDatabase) {
    fun findByUsername(username: String) =
        db.rawQuery("SELECT * FROM users WHERE username = '" + username + "'", null)
}
`
    },
    negative: {
      file: "app/src/main/java/com/example/app/UserDao.kt",
      content: `package com.example.app

import android.database.sqlite.SQLiteDatabase

class UserDao(private val db: SQLiteDatabase) {
    fun findByUsername(username: String) =
        db.rawQuery("SELECT * FROM users WHERE username = ?", arrayOf(username))
}
`
    },
    note: "Negative uses a parameterized placeholder with a selectionArgs array instead of string concatenation, so no '+' appears on the rawQuery line, which is what the rule's concatenation check requires."
  },
  {
    ruleId: "ANDROID_PENDING_INTENT_MUTABLE",
    check: "mobile-android",
    positive: {
      file: "app/src/main/java/com/example/app/NotificationHelper.kt",
      content: `package com.example.app

import android.app.PendingIntent
import android.content.Context
import android.content.Intent

class NotificationHelper(private val context: Context) {
    fun buildResultPendingIntent(requestCode: Int): PendingIntent {
        val intent = Intent("com.example.app.ACTION_RESULT")
        return PendingIntent.getBroadcast(context, requestCode, intent, PendingIntent.FLAG_MUTABLE)
    }
}
`
    },
    negative: {
      file: "app/src/main/java/com/example/app/NotificationHelper.kt",
      content: `package com.example.app

import android.app.PendingIntent
import android.content.Context
import android.content.Intent

class NotificationHelper(private val context: Context) {
    fun buildResultPendingIntent(requestCode: Int): PendingIntent {
        val intent = Intent(context, ResultReceiver::class.java)
        intent.setPackage(context.packageName)
        return PendingIntent.getBroadcast(context, requestCode, intent, PendingIntent.FLAG_IMMUTABLE)
    }
}
`
    },
    note: "The rule fires unconditionally on the literal substring FLAG_MUTABLE. Negative uses FLAG_IMMUTABLE (which does not contain that substring) together with an explicit, package-scoped Intent, exactly as requiredActions recommends."
  },
  {
    ruleId: "ANDROID_WEBVIEW_SSL_PROCEED",
    check: "mobile-android",
    positive: {
      file: "app/src/main/java/com/example/app/SecureWebViewClient.java",
      content: `package com.example.app;

import android.net.http.SslError;
import android.webkit.SslErrorHandler;
import android.webkit.WebView;
import android.webkit.WebViewClient;

public class SecureWebViewClient extends WebViewClient {
    @Override
    public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
        // Ignore SSL errors and continue loading regardless of certificate validity
        handler.proceed();
    }
}
`
    },
    negative: {
      file: "app/src/main/java/com/example/app/SecureWebViewClient.java",
      content: `package com.example.app;

import android.net.http.SslError;
import android.webkit.SslErrorHandler;
import android.webkit.WebView;
import android.webkit.WebViewClient;

public class SecureWebViewClient extends WebViewClient {
    @Override
    public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
        // Never bypass certificate validation errors
        handler.cancel();
    }
}
`
    },
    note: "Negative calls handler.cancel() instead of handler.proceed(), so the substring handler.proceed() the rule scans for within 300 chars of onReceivedSslError never appears."
  },

  // ---------------------------------------------------------------------------
  // build.gradle.kts — checkGradleSdkVersions()
  // ---------------------------------------------------------------------------
  {
    ruleId: "ANDROID_MIN_SDK_LOW",
    check: "mobile-android",
    positive: {
      file: "app/build.gradle.kts",
      content: `android {
    compileSdk = 34

    defaultConfig {
        applicationId = "com.example.app"
        minSdkVersion = 19
        targetSdkVersion = 34
        versionCode = 1
        versionName = "1.0"
    }
}
`
    },
    negative: {
      file: "app/build.gradle.kts",
      content: `android {
    compileSdk = 34

    defaultConfig {
        applicationId = "com.example.app"
        minSdkVersion = 26
        targetSdkVersion = 34
        versionCode = 1
        versionName = "1.0"
    }
}
`
    },
    note: "Negative raises minSdkVersion to 26, above both the <21 (CRITICAL) and <24 (MEDIUM) thresholds the rule checks, in line with requiredActions' 24+/28+ guidance."
  },

  // ---------------------------------------------------------------------------
  // Flutter — checkFlutterSharedPrefs()
  // ---------------------------------------------------------------------------
  {
    ruleId: "FLUTTER_INSECURE_STORAGE",
    check: "mobile-android",
    positive: {
      file: "lib/services/auth_storage.dart",
      content: `import 'package:shared_preferences/shared_preferences.dart';

class AuthStorage {
  Future<void> saveAuthToken(String token) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('auth_token', token);
  }
}
`
    },
    negative: {
      file: "lib/services/auth_storage.dart",
      content: `import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class AuthStorage {
  final FlutterSecureStorage _storage = const FlutterSecureStorage();

  Future<void> saveAuthToken(String token) async {
    await _storage.write(key: 'auth_token', value: token);
  }
}
`
    },
    note: "Negative never imports shared_preferences, never calls SharedPreferences.getInstance(), and never calls prefs.setString(...) — it uses flutter_secure_storage end to end (Keychain/Keystore-backed), the package's own recommended migration target."
  },

  // ---------------------------------------------------------------------------
  // Firebase rules — checkFirebasePublicRules()
  // ---------------------------------------------------------------------------
  {
    ruleId: "ANDROID_FIREBASE_PUBLIC_RULES",
    check: "mobile-android",
    positive: {
      file: "firestore.rules",
      content: `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if true;
    }
  }
}
`
    },
    negative: {
      file: "firestore.rules",
      content: `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
  }
}
`
    },
    note: "Negative requires request.auth != null and ownership match instead of a bare if true — no '.read'/'.write' wildcard grant and no literal 'if true' substring remain for the rule's pattern to match."
  }
];
