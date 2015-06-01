/*
 * Copyright (C) 2013 The auzone Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.auzone.account.gcm;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.app.IntentService;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.os.PowerManager;
import android.util.Log;
import com.android.volley.Response;
import com.android.volley.VolleyError;
import com.auzone.account.AuzoneAccount;
import com.auzone.account.api.DeviceFinderService;
import com.auzone.account.api.request.SendChannelRequestBody;
import com.auzone.account.auth.AuthClient;
import com.auzone.account.encryption.ECDHKeyService;
import com.auzone.account.gcm.model.EncryptedMessage;
import com.auzone.account.gcm.model.GCMessage;
import com.auzone.account.gcm.model.PlaintextMessage;
import com.auzone.account.provider.AuzoneAccountProvider;
import com.auzone.account.util.AuzoneAccountUtils;
import com.auzone.account.util.EncryptionUtils;
import com.google.gson.Gson;
import com.google.gson.JsonParseException;

import org.spongycastle.crypto.params.ECPrivateKeyParameters;
import org.spongycastle.crypto.params.ECPublicKeyParameters;

import java.math.BigInteger;

/**
 * Created by ctso on 8/3/13.
 */
public class GCMIntentService extends IntentService implements Response.Listener<Integer>, Response.ErrorListener {

    private static final String TAG = GCMIntentService.class.getSimpleName();
    protected static final String ACTION_RECEIVE = "com.auzone.account.gcm.RECEIVE";

    private static PowerManager.WakeLock sWakeLock;
    private static final int WAKE_LOCK_TIMEOUT = 1000 * 60 * 5;

    private Context mContext;
    private Account mAccount;
    private AuthClient mAuthClient;
    private Gson mGson;
    private byte[] mHmacSecret;

    public GCMIntentService() {
        super(TAG);
        mGson = new Gson();
    }

    @Override
    protected void onHandleIntent(Intent intent) {
        mContext = getApplicationContext();
        mAuthClient = AuthClient.getInstance(mContext);
        mAccount = AuzoneAccountUtils.getAuzoneAccountAccount(mContext);
        mHmacSecret = AuzoneAccountUtils.getHmacSecret(mContext);
        acquireWakeLock();

        // Drop the intent if it isn't a GCM message.
        if (!ACTION_RECEIVE.equals(intent.getAction())) {
            return;
        }

        if (mAccount == null) {
            if (AuzoneAccount.DEBUG) Log.d(TAG, "No AuzoneAccount Configured!");
            return;
        }

        String messageData = intent.getExtras().getString("data");
        if (AuzoneAccount.DEBUG) Log.d(TAG, "message data = " + messageData);

        GCMessage message = mGson.fromJson(messageData, GCMessage.class);
        handleMessage(message);
    }

    private void acquireWakeLock() {
        if (sWakeLock == null) {
            PowerManager pm = (PowerManager)
                    mContext.getSystemService(Context.POWER_SERVICE);
            sWakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, TAG);
        }
        if (!sWakeLock.isHeld()) {
            if (AuzoneAccount.DEBUG) Log.v(TAG, "Acquiring " + WAKE_LOCK_TIMEOUT + " ms wakelock");
            sWakeLock.acquire(WAKE_LOCK_TIMEOUT);
        }
    }

    private void handleMessage(final GCMessage message) {
        if (AuzoneAccount.DEBUG) Log.d(TAG, "gson parsed message = " + message.toJson());

        /**
         * Because we allow one device to be tied to multiple users, we need to verify that the
         * message is intended for the current user.  The server adds the account parameter so that
         * it cannot be tampered with.  This is primarily to protect against password reset messages
         * being processed for the wrong account.
         */
        String account = message.getAccount();
        if (account != null && !account.equals(mAccount.name)) {
            Log.w(TAG, "Received message for " + account  + " but current user is " + mAccount.name);
            return;
        }

        if (GCMessage.COMMAND_SECURE_MESSAGE.equals(message.getCommand())) {
            handleSecureMessage(message);
        } else if (PlaintextMessage.COMMAND_PASSWORD_RESET.equals(message.getCommand())) {
            handlePasswordReset();
        } else if (PlaintextMessage.COMMAND_PUBLIC_KEYS_EXHAUSTED.equals(message.getCommand())) {
            handlePublicKeysExhausted();
        }
    }

    private void handleSecureMessage(final GCMessage message) {
        EncryptedMessage encryptedMessage;
        try {
            encryptedMessage = EncryptedMessage.fromJson(message.getPayload());
        } catch (JsonParseException e) {
            Log.e(TAG, "JsonParseException while parsing payload", e);
            throw new AssertionError(e);
        }

        String keyId = encryptedMessage.getKeyId();

        // Verify payload signature and sequence
        if (!validateMessage(message, keyId)) {
            sendFailureMessage();
            deletePublicKey(keyId);
            Log.w(TAG, "Unable to verify message");
            return;
        }

        // Derive symmetric key from our private key and remote public key.
        // Note: Because we only expect one message, there is no need to handle the case where only a key_id
        // is provided.  In the future, if we expect additional encrypted messages from the browser we should
        // look up the symmetric key if a public key is not provided.
        ECPublicKeyParameters remotePublicKey = encryptedMessage.getPublicKey();
        ECPrivateKeyParameters privateKey = getPrivateKey(keyId);
        if (privateKey == null) {
            sendFailureMessage();
            return;
        }
        byte[] symmetricKey = EncryptionUtils.ECDH.calculateSecret(privateKey, remotePublicKey);
        storeSymmetricKey(keyId, symmetricKey);
        deletePublicKey(keyId);

        // Decrypt the message
        String plaintextMessageJson = EncryptionUtils.AES.decrypt(encryptedMessage.getCiphertext(), symmetricKey);
        PlaintextMessage plaintextMessage = mGson.fromJson(plaintextMessageJson, PlaintextMessage.class);

        if (PlaintextMessage.COMMAND_BEGIN_LOCATE.equals(plaintextMessage.getCommand())) {
            handleBeginLocate(keyId);
        } else if (PlaintextMessage.COMMAND_BEGIN_WIPE.equals(plaintextMessage.getCommand())) {
            handleBeginWipe(keyId);
        }
    }

    private boolean validateSignature(GCMessage message) {
        String signatureBody = message.getSequence() + ":" + message.getPayload();
        String localSignature = EncryptionUtils.HMAC.getSignature(mHmacSecret, signatureBody);
        if (message.getSignature().equals(localSignature)) {
            return true;
        } else {
            Log.w(TAG, "Local signature " + localSignature + " does not match remote signature " + message.getSignature());
            return false;
        }
    }

    private boolean validateSequence(GCMessage message, String keyId) {
        AuthClient.SymmetricKeySequencePair keySequencePair = mAuthClient.getSymmetricKey(keyId);
        if (keySequencePair != null && keySequencePair.getLocalSequence() >= message.getSequence()) {
            Log.w(TAG, "Local sequence " + keySequencePair.getLocalSequence() + " is invalid for keyId: " + keyId);
            return false;
        } else if (keySequencePair == null && message.getSequence() >= 0) {
            return true;
        } else {
            mAuthClient.incrementSessionLocalSequence(keyId);
            return true;
        }
    }

    private boolean validateMessage(GCMessage message, String keyId) {
        return validateSignature(message) && validateSequence(message, keyId);
    }

    private ECPrivateKeyParameters getPrivateKey(String keyId) {
        String[] projection = new String[] { AuzoneAccountProvider.ECDHKeyStoreColumns.PRIVATE };
        String selection = AuzoneAccountProvider.ECDHKeyStoreColumns.KEY_ID + " = ?";
        String[] selectionArgs = new String[] { keyId };
        Cursor cursor = mContext.getContentResolver().query(AuzoneAccountProvider.ECDH_CONTENT_URI, projection, selection, selectionArgs, null);
        if (cursor.getCount() != 1) {
            return null;
        }

        cursor.moveToFirst();
        String privateKeyString = cursor.getString(cursor.getColumnIndex(AuzoneAccountProvider.ECDHKeyStoreColumns.PRIVATE));
        cursor.close();

        BigInteger privateKeyBigInteger = new BigInteger(AuzoneAccountUtils.decodeHex(privateKeyString));
        return new ECPrivateKeyParameters(privateKeyBigInteger, EncryptionUtils.ECDH.DOMAIN_PARAMETERS);
    }

    private void deletePublicKey(String keyId) {
        String selection = AuzoneAccountProvider.ECDHKeyStoreColumns.KEY_ID + " = ?";
        String[] selectionArgs = new String[] { keyId };
        mContext.getContentResolver().delete(AuzoneAccountProvider.ECDH_CONTENT_URI, selection, selectionArgs);

        // Generate more public keys.
        ECDHKeyService.startGenerate(mContext);
    }

    private void storeSymmetricKey(String keyId, byte[] symmetricKey) {
        String symmetricKeyHex = AuzoneAccountUtils.encodeHex(symmetricKey);
        if (AuzoneAccount.DEBUG) Log.v(TAG, "Storing symmetric key " + symmetricKeyHex + " for keyId " + keyId);
        ContentValues values = new ContentValues();
        values.put(AuzoneAccountProvider.SymmetricKeyStoreColumns.KEY_ID, keyId);
        values.put(AuzoneAccountProvider.SymmetricKeyStoreColumns.KEY, symmetricKeyHex);
        mContext.getContentResolver().insert(AuzoneAccountProvider.SYMMETRIC_KEY_CONTENT_URI, values);
    }

    private void sendFailureMessage() {
        PlaintextMessage keyExchangeFailedMessage = new PlaintextMessage(PlaintextMessage.COMMAND_KEY_EXCHANGE_FAILED);
        String deviceId = AuzoneAccountUtils.getUniqueDeviceId(mContext);
        SendChannelRequestBody sendChannelRequestBody = new SendChannelRequestBody(PlaintextMessage.COMMAND_KEY_EXCHANGE_FAILED, deviceId, keyExchangeFailedMessage);
        mAuthClient.sendChannel(sendChannelRequestBody, this, this);
    }

    private void handleBeginLocate(String keyId) {
        if (AuzoneAccount.DEBUG) Log.d(TAG, "Handling begin_locate command");
        DeviceFinderService.reportLocation(mContext, mAccount, keyId);
    }

    private void handleBeginWipe(String keyId) {
        if (AuzoneAccount.DEBUG) Log.d(TAG, "Handling begin_wipe command");
        mAuthClient.destroyDevice(mContext, keyId);
    }

    private void handlePasswordReset() {
        AccountManager accountManager = (AccountManager) mContext.getSystemService(ACCOUNT_SERVICE);
        if (AuzoneAccount.DEBUG) Log.d(TAG, "Got password reset message, expiring access and refresh tokens");
        mAuthClient.expireToken(accountManager, mAccount);
        mAuthClient.expireRefreshToken(accountManager, mAccount);
        mAuthClient.notifyPasswordChange(mAccount);
    }

    private void handlePublicKeysExhausted() {
        mContext.getContentResolver().delete(AuzoneAccountProvider.ECDH_CONTENT_URI, null, null);
        ECDHKeyService.startGenerate(mContext);
    }

    @Override
    public void onErrorResponse(VolleyError volleyError) {
        if (AuzoneAccount.DEBUG) volleyError.printStackTrace();
    }

    @Override
    public void onResponse(Integer integer) {
        if (AuzoneAccount.DEBUG) Log.d(TAG, "sendChannel response="+integer);
    }
}
