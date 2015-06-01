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

package com.auzone.account.auth;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.accounts.AccountManagerCallback;
import android.accounts.AccountManagerFuture;
import android.accounts.AuthenticatorException;
import android.accounts.OnAccountsUpdateListener;
import android.accounts.OperationCanceledException;
import android.app.AppGlobals;
import android.app.Notification;
import android.app.PendingIntent;
import android.app.admin.DevicePolicyManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.graphics.drawable.BitmapDrawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.PowerManager;
import android.os.SystemProperties;
import android.telephony.TelephonyManager;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import com.android.volley.NetworkResponse;
import com.android.volley.Request;
import com.android.volley.RequestQueue;
import com.android.volley.Response;
import com.android.volley.Response.ErrorListener;
import com.android.volley.Response.Listener;
import com.android.volley.VolleyError;
import com.android.volley.toolbox.RequestFuture;
import com.android.volley.toolbox.Volley;
import com.auzone.account.AuzoneAccount;
import com.auzone.account.R;
import com.auzone.account.api.AuthTokenRequest;
import com.auzone.account.api.AuthTokenResponse;
import com.auzone.account.api.CreateProfileRequest;
import com.auzone.account.api.CreateProfileResponse;
import com.auzone.account.api.PingRequest;
import com.auzone.account.api.PingResponse;
import com.auzone.account.api.PingService;
import com.auzone.account.api.ProfileAvailableRequest;
import com.auzone.account.api.ProfileAvailableResponse;
import com.auzone.account.api.SendChannelRequest;
import com.auzone.account.api.request.AddPublicKeysRequest;
import com.auzone.account.api.request.AddPublicKeysRequestBody;
import com.auzone.account.api.request.GetMinimumAppVersionRequest;
import com.auzone.account.api.request.GetPublicKeyIdsRequest;
import com.auzone.account.api.request.SendChannelRequestBody;
import com.auzone.account.api.response.AddPublicKeysResponse;
import com.auzone.account.api.response.GetMinimumAppVersionResponse;
import com.auzone.account.api.response.GetPublicKeyIdsResponse;
import com.auzone.account.gcm.GCMUtil;
import com.auzone.account.gcm.model.WipeStartedMessage;
import com.auzone.account.provider.AuzoneAccountProvider;
import com.auzone.account.util.AuzoneAccountUtils;
import com.auzone.account.util.EncryptionUtils;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParseException;

import java.io.IOException;
import java.util.concurrent.ExecutionException;

public class AuthClient {

    private static final String TAG = AuthClient.class.getSimpleName();
    private static final int API_VERSION = 1;
    private static final String API_ROOT = "/api/v" + API_VERSION;
    private static final String ACCOUNT_METHOD = "/account";
    private static final String REGISTER_METHOD = "/register";
    private static final String AVAILABLE_METHOD = "/available";
    private static final String DEVICE_METHOD = "/device";
    private static final String PING_METHOD = "/ping";
    private static final String SECMSG_METHOD = "/secmsg";
    private static final String SEND_CHANNEL_METHOD = "/send_channel";
    private static final String ADD_PUBLIC_KEYS_METHOD = "/add_public_keys";
    private static final String GET_PUBLIC_KEY_IDS_METHOD = "/get_public_key_ids";
    private static final String GET_MINIMUM_APP_VERSION_METHOD = "/get_minimum_app_version";
    private static final String HELP_PATH = "/help";
    private static final String SERVER_URI = getServerURI();

    public static final String AUTH_URI = SERVER_URI + "/oauth2/token";
    public static final String REGISTER_PROFILE_URI = SERVER_URI + API_ROOT + ACCOUNT_METHOD + REGISTER_METHOD;
    public static final String PROFILE_AVAILABLE_URI = SERVER_URI + API_ROOT + ACCOUNT_METHOD + AVAILABLE_METHOD;
    public static final String PING_URI = SERVER_URI + API_ROOT + DEVICE_METHOD + PING_METHOD;
    public static final String SEND_CHANNEL_URI = SERVER_URI + API_ROOT + SECMSG_METHOD + SEND_CHANNEL_METHOD;
    public static final String ADD_PUBLIC_KEYS_URI = SERVER_URI + API_ROOT + DEVICE_METHOD + ADD_PUBLIC_KEYS_METHOD;
    public static final String GET_PUBLIC_KEY_IDS_URI = SERVER_URI + API_ROOT + DEVICE_METHOD + GET_PUBLIC_KEY_IDS_METHOD;
    public static final String GET_MINIMUM_APP_VERSION_URI = SERVER_URI + API_ROOT + PING_METHOD + GET_MINIMUM_APP_VERSION_METHOD;
    public static final String LEARN_MORE_URI = SERVER_URI + HELP_PATH;
    public static final String TOS_URI = "https://cyngn.com/legal/terms-of-service";
    public static final String PRIVACY_POLICY_URI = "https://cyngn.com/legal/privacy-policy";

    private static final String CLIENT_ID = "8001";
    private static final String SECRET = "b93bb90299bb46f3bafdd6ca630c8f3c";

    public static final String ENCODED_ID_SECRET = new String(Base64.encode((CLIENT_ID + ":" + SECRET).getBytes(), Base64.NO_WRAP));

    private RequestQueue mRequestQueue;

    private static AuthClient sInstance;
    private Context mContext;
    private AccountManager mAccountManager;

    private Request<?> mInFlightPingRequest;
    private Request<?> mInFlightTokenRequest;
    private Request<?> mInFlightAuthTokenRequest;
    private Request<?> mInFlightChannelRequest;
    private Request<?> mInFlightAddPublicKeysRequest;
    private Request<?> mInFlightGetPublicKeyIdsRequest;
    private Request<?> mInFlightGetMinimumAppVersionRequest;

    private OnAccountsUpdateListener mAccountsUpdateListener;

    private Gson mExcludingGson;
    private Gson mGson;

    private final Handler mHandler = new Handler();

    private AuthClient(Context context) {
        mContext = context.getApplicationContext();
        mAccountManager = AccountManager.get(mContext);
        mRequestQueue = Volley.newRequestQueue(mContext);
        mExcludingGson = new GsonBuilder().excludeFieldsWithoutExposeAnnotation().create();
        mGson = new Gson();
    }

    public static final AuthClient getInstance(Context context) {
        if (sInstance == null) sInstance = new AuthClient(context);
        return sInstance;
    }


    public AuthTokenResponse blockingLogin(String accountName, String password) throws VolleyError {
        RequestFuture<AuthTokenResponse> future = RequestFuture.newFuture();
        if (mInFlightAuthTokenRequest != null) {
            mInFlightAuthTokenRequest.cancel();
            mInFlightAuthTokenRequest = null;
        }
        mInFlightAuthTokenRequest = mRequestQueue.add(new AuthTokenRequest(accountName, AuzoneAccountUtils.digest("SHA512", password), future, future));
        try {
            AuthTokenResponse response = future.get();
            return response;
        } catch (InterruptedException e) {
            throw new VolleyError(e);
        } catch (ExecutionException e) {
            throw new VolleyError(e);
        } finally {
            mInFlightAuthTokenRequest = null;
        }
    }

    public Request<?> login(String accountName, String password, Listener<AuthTokenResponse> listener, ErrorListener errorListener) {
        return mRequestQueue.add(new AuthTokenRequest(accountName, password, listener, errorListener));
    }

    public AuthTokenResponse blockingRefreshAccessToken(String refreshToken) throws VolleyError {
        RequestFuture<AuthTokenResponse> future = RequestFuture.newFuture();
        if (mInFlightAuthTokenRequest != null) {
            mInFlightAuthTokenRequest.cancel();
            mInFlightAuthTokenRequest = null;
        }
        mInFlightAuthTokenRequest = mRequestQueue.add(new AuthTokenRequest(refreshToken, future, future));
        try {
            AuthTokenResponse response = future.get();
            return response;
        } catch (InterruptedException e) {
            throw new VolleyError(e);
        } catch (ExecutionException e) {
            throw new VolleyError(e);
        } finally {
            mInFlightAuthTokenRequest = null;
        }
    }

    public Request<?> refreshAccessToken(String refreshToken, Listener<AuthTokenResponse> listener, ErrorListener errorListener) {
        return mRequestQueue.add(new AuthTokenRequest(refreshToken, listener, errorListener));
    }

    public Request<?> createProfile(String email, String password, boolean termsOfService,
            Listener<CreateProfileResponse> listener, ErrorListener errorListener) {
        return mRequestQueue.add(new CreateProfileRequest(email, password, termsOfService, listener, errorListener));
    }

    public Request<?> checkProfile(String email, Listener<ProfileAvailableResponse> listener, ErrorListener errorListener) {
        return mRequestQueue.add(new ProfileAvailableRequest(email, listener, errorListener));
    }

    public void pingService(final Listener<PingResponse> listener, final ErrorListener errorListener) {
        final Account account = AuzoneAccountUtils.getAuzoneAccountAccount(mContext);
        if (account == null) {
            if (AuzoneAccount.DEBUG) Log.d(TAG, "No AuzoneAccount Configured!");
            return;
        }
        final TokenCallback callback = new TokenCallback() {
            @Override
            public void onTokenReceived(final String token) {
                if (mInFlightPingRequest != null) {
                    mInFlightPingRequest.cancel();
                    mInFlightPingRequest = null;
                }
                mInFlightPingRequest = mRequestQueue.add(new PingRequest(mContext, AuzoneAccountUtils.getUniqueDeviceId(mContext), token, getCarrierName(),
                        new Listener<PingResponse>() {
                            @Override
                            public void onResponse(PingResponse pingResponse) {
                                mInFlightPingRequest = null;
                                if (AuzoneAccount.DEBUG) Log.d(TAG, "pingService onResponse() : " + pingResponse.getStatusCode());
                                if (listener != null) {
                                    listener.onResponse(pingResponse);
                                }
                            }
                        },
                        new ErrorListener() {
                            @Override
                            public void onErrorResponse(VolleyError volleyError) {
                                mInFlightPingRequest = null;
                                if (volleyError.networkResponse == null) {
                                    if (AuzoneAccount.DEBUG) Log.d(TAG, "pingService onErrorResponse() no response");
                                    volleyError.printStackTrace();
                                    errorListener.onErrorResponse(volleyError);
                                    return;
                                }
                                int statusCode = volleyError.networkResponse.statusCode;
                                if (AuzoneAccount.DEBUG) Log.d(TAG, "pingService onErrorResponse() : " + statusCode);
                                if (statusCode == 401) {
                                    expireToken(mAccountManager, account);
                                    pingService(listener, errorListener);
                                }
                            }
                        }));
            }

            @Override
            public void onError(VolleyError error) {
                if (AuzoneAccount.DEBUG) {
                    Log.d(TAG, "pingService onError(): ");
                    error.printStackTrace();
                }
                if (errorListener != null) {
                    errorListener.onErrorResponse(error);
                }
            }
        };

        doTokenRequest(account, callback);
    }

    public void addPublicKeys(final AddPublicKeysRequestBody requestBody, final Listener<AddPublicKeysResponse> listener, final ErrorListener errorListener) {
        final Account account = AuzoneAccountUtils.getAuzoneAccountAccount(mContext);
        if (account == null) {
            if (AuzoneAccount.DEBUG) Log.d(TAG, "No AuzoneAccount Configured!");
            return;
        }

        // Convert the message to JSON
        final String requestBodyJson = requestBody.toJson(mGson);

        if (AuzoneAccount.DEBUG) Log.d(TAG, "Sending public keys to server, content = " + requestBodyJson);
        final TokenCallback callback = new TokenCallback() {
            @Override
            public void onTokenReceived(String token) {
                if (mInFlightAddPublicKeysRequest != null) {
                    mInFlightAddPublicKeysRequest.cancel();
                    mInFlightAddPublicKeysRequest = null;
                }

                mInFlightAddPublicKeysRequest = mRequestQueue.add(new AddPublicKeysRequest(token, requestBodyJson,
                        new Listener<AddPublicKeysResponse>() {
                            @Override
                            public void onResponse(AddPublicKeysResponse addPublicKeysResponse) {
                                mInFlightAddPublicKeysRequest = null;
                                if (listener != null) {
                                    listener.onResponse(addPublicKeysResponse);
                                }
                            }
                        },
                        new ErrorListener() {
                            @Override
                            public void onErrorResponse(VolleyError volleyError) {
                                mInFlightChannelRequest = null;
                                if (volleyError.networkResponse == null) {
                                    if (AuzoneAccount.DEBUG) Log.d(TAG, "addPublicKeys() onErrorResponse no response");
                                    volleyError.printStackTrace();
                                    errorListener.onErrorResponse(volleyError);
                                    return;
                                }
                                int statusCode = volleyError.networkResponse.statusCode;
                                if (AuzoneAccount.DEBUG) Log.d(TAG, "addPublicKeys onErrorResponse() : " + statusCode);
                                if (statusCode == 401) {
                                    expireToken(mAccountManager, account);
                                    addPublicKeys(requestBody, listener, errorListener);
                                } else {
                                    errorListener.onErrorResponse(volleyError);
                                }
                            }
                        }
                ));
            }

            @Override
            public void onError(VolleyError error) {
                if (errorListener != null) {
                    errorListener.onErrorResponse(error);
                }
            }
        };

        doTokenRequest(account, callback);
    }

    public void getPublicKeyIds(final Listener<GetPublicKeyIdsResponse> listener, final ErrorListener errorListener) {
        final Account account = AuzoneAccountUtils.getAuzoneAccountAccount(mContext);
        if (account == null) {
            if (AuzoneAccount.DEBUG) Log.d(TAG, "No AuzoneAccount Configured!");
            return;
        }

        final TokenCallback callback = new TokenCallback() {
            @Override
            public void onTokenReceived(String token) {
                if (mInFlightGetPublicKeyIdsRequest != null) {
                    mInFlightGetPublicKeyIdsRequest.cancel();
                    mInFlightGetPublicKeyIdsRequest = null;
                }

                mInFlightGetPublicKeyIdsRequest = mRequestQueue.add(new GetPublicKeyIdsRequest(mContext, token, new Listener<GetPublicKeyIdsResponse>() {
                    @Override
                    public void onResponse(GetPublicKeyIdsResponse getPublicKeyIdsResponse) {
                        mInFlightGetPublicKeyIdsRequest = null;
                        if (listener != null) {
                            listener.onResponse(getPublicKeyIdsResponse);
                        }
                    }
                },
                new ErrorListener() {
                    @Override
                    public void onErrorResponse(VolleyError volleyError) {
                        mInFlightGetPublicKeyIdsRequest = null;
                        if (volleyError.networkResponse == null) {
                            if (AuzoneAccount.DEBUG) Log.d(TAG, "getPublicKeyIds() onErrorResponse no response");
                            volleyError.printStackTrace();
                            errorListener.onErrorResponse(volleyError);
                        }
                        int statusCode = volleyError.networkResponse.statusCode;
                        if (AuzoneAccount.DEBUG) Log.d(TAG, "getPublicKeyIds onErrorResponse() : " + statusCode);
                        if (statusCode == 401) {
                            expireToken(mAccountManager, account);
                            getPublicKeyIds(listener, errorListener);
                        } else {
                            errorListener.onErrorResponse(volleyError);
                        }
                    }
                }
                ));
            }

            @Override
            public void onError(VolleyError error) {

            }
        };

        doTokenRequest(account, callback);
    }

    public void sendChannel(final SendChannelRequestBody sendChannelRequestBody, final Listener<Integer> listener, final ErrorListener errorListener) {
        final Account account = AuzoneAccountUtils.getAuzoneAccountAccount(mContext);
        if (account == null) {
            if (AuzoneAccount.DEBUG) Log.d(TAG, "No AuzoneAccount Configured!");
            return;
        }

        // Since we are sending a message, bump the remote sequence.
        if (sendChannelRequestBody.getKeyId() != null) {
            incrementSessionRemoteSequence(sendChannelRequestBody.getKeyId());
        }

        // Convert the message to JSON using the appropriate Gson instance.
        final String sendChannelRequestBodyJson = sendChannelRequestBody.toJson();

        if (AuzoneAccount.DEBUG) Log.d(TAG, "Sending secure message, encrypted content = " + sendChannelRequestBody.toJsonPretty());

        final TokenCallback callback = new TokenCallback() {
            @Override
            public void onTokenReceived(String token) {
                if (mInFlightChannelRequest != null) {
                    mInFlightChannelRequest.cancel();
                    mInFlightChannelRequest = null;
                }

                mInFlightChannelRequest = mRequestQueue.add(new SendChannelRequest(token, sendChannelRequestBodyJson,
                        new Listener<Integer>() {
                            @Override
                            public void onResponse(Integer integer) {
                                mInFlightChannelRequest = null;
                                if (listener != null) {
                                    listener.onResponse(integer);
                                }
                            }
                        },
                        new ErrorListener() {
                            @Override
                            public void onErrorResponse(VolleyError volleyError) {
                                mInFlightChannelRequest = null;
                                if (volleyError.networkResponse == null) {
                                    if (AuzoneAccount.DEBUG) Log.d(TAG, "sendChannel() onErrorResponse no response");
                                    volleyError.printStackTrace();
                                    errorListener.onErrorResponse(volleyError);
                                    return;
                                }
                                int statusCode = volleyError.networkResponse.statusCode;
                                if (AuzoneAccount.DEBUG) Log.d(TAG, "sendChannel onErrorResponse() : " + statusCode);
                                if (statusCode == 401) {
                                    expireToken(mAccountManager, account);
                                    sendChannel(sendChannelRequestBody, listener, errorListener);
                                }
                            }
                        }
                ));
            }

            @Override
            public void onError(VolleyError error) {
                if (errorListener != null) {
                    errorListener.onErrorResponse(error);
                }
            }
        };

        doTokenRequest(account, callback);
    }

    public Request<?> getMinimumAppVersion(final Listener<GetMinimumAppVersionResponse> listener, final ErrorListener errorListener) {
        if (mInFlightGetMinimumAppVersionRequest != null) {
            mInFlightGetMinimumAppVersionRequest.cancel();
            mInFlightGetMinimumAppVersionRequest = null;
        }
        mInFlightGetMinimumAppVersionRequest = new GetMinimumAppVersionRequest(new Listener<String>() {
            @Override
            public void onResponse(String response) {
                mInFlightGetMinimumAppVersionRequest = null;
                try {
                    GetMinimumAppVersionResponse getMinimumAppVersionResponse = mGson.fromJson(response, GetMinimumAppVersionResponse.class);
                    if (listener != null) {
                        listener.onResponse(getMinimumAppVersionResponse);
                    }
                } catch (JsonParseException e) {
                    errorListener.onErrorResponse(new VolleyError(e));
                }
            }
        }, new ErrorListener() {
            @Override
            public void onErrorResponse(VolleyError volleyError) {
                mInFlightGetMinimumAppVersionRequest = null;
                if (volleyError.networkResponse == null) {
                    if (AuzoneAccount.DEBUG) Log.d(TAG, "getMinimumAppVersion() onErrorResponse no response");
                    volleyError.printStackTrace();
                    errorListener.onErrorResponse(volleyError);
                    return;
                }
            }
        });
        mRequestQueue.add(mInFlightGetMinimumAppVersionRequest);
        return mInFlightGetMinimumAppVersionRequest;
    }

    public void addLocalAccount(final AccountManager accountManager, final Account account, String password, AuthTokenResponse response) {
        mAccountsUpdateListener = new OnAccountsUpdateListener() {
            @Override
            public void onAccountsUpdated(Account[] accounts) {
                for (Account updatedAccount : accounts) {
                    if (updatedAccount.type.equals(AuzoneAccount.ACCOUNT_TYPE_AuzoneAccount) && AuzoneAccountUtils.getAuzoneAccountAccount(mContext) != null) {
                        if (GCMUtil.googleServicesExist(mContext)) {
                            GCMUtil.registerForGCM(mContext);
                        } else {
                            PingService.pingServer(mContext);
                        }
                        mAccountManager.removeOnAccountsUpdatedListener(mAccountsUpdateListener);
                    }
                }
            }
        };
        mAccountManager.addOnAccountsUpdatedListener(mAccountsUpdateListener, new Handler(), false);
        accountManager.addAccountExplicitly(account, response.getRefreshToken(), null);
        updateLocalAccount(accountManager, account, response);
        generateEncryptionExtras(account, password);
        AuzoneAccountUtils.hideNotification(mContext, AuzoneAccount.NOTIFICATION_ID_PASSWORD_RESET);
    }

    public void updateLocalAccount(AccountManager accountManager, Account account, AuthTokenResponse response) {
        accountManager.setUserData(account, AuzoneAccount.AUTHTOKEN_TYPE_ACCESS, response.getAccessToken());
        accountManager.setAuthToken(account, AuzoneAccount.AUTHTOKEN_TYPE_ACCESS, response.getAccessToken());
        accountManager.setUserData(account, AuzoneAccount.AUTHTOKEN_EXPIRES_IN, String.valueOf(System.currentTimeMillis() + (Long.valueOf(response.getExpiresIn()) * 1000)));
        if (AuzoneAccount.DEBUG) {
            Log.d(TAG, "Access token Expires in = " + (Long.valueOf(response.getExpiresIn()) * 1000) + "ms");
        }
    }

    private void doTokenRequest(final Account account, final TokenCallback tokenCallback) {
        final String currentToken = mAccountManager.peekAuthToken(account, AuzoneAccount.AUTHTOKEN_TYPE_ACCESS);
        if (AuzoneAccount.DEBUG) Log.d(TAG, "doTokenRequest() peekAuthToken:  " + currentToken);
        if (isTokenExpired(mAccountManager, account) || currentToken == null) {
            if (AuzoneAccount.DEBUG) Log.d(TAG, "doTokenRequest() isTokenExpired:  " + "true");
            mAccountManager.invalidateAuthToken(AuzoneAccount.ACCOUNT_TYPE_AuzoneAccount, currentToken);
            final String refreshToken = getRefreshToken(account);
            if (mInFlightTokenRequest != null) {
                mInFlightTokenRequest.cancel();
                mInFlightTokenRequest = null;
            }

            if (refreshToken == null) {
                // Drop the request, we shouldn't even bother retrying if we don't have a refresh
                // token.
                // TODO(ctso): If we don't drop the request, a bunch of NPEs get thrown by Volley.
                // TODO(ctso): Need to track this down, ideally we send a MissingRefreshToken exception
                // TODO(ctso): so we can cancel the network request.  Services like DeviceFinderService
                // TODO(ctso): will continue to run unless we pass an error back to it.
                Log.w(TAG, "Missing refresh token, dropping request.");
                notifyPasswordChange(account);
                return;
            }

            mInFlightTokenRequest = refreshAccessToken(refreshToken,
                    new Listener<AuthTokenResponse>() {
                        @Override
                        public void onResponse(AuthTokenResponse authTokenResponse) {
                            mInFlightTokenRequest = null;
                            if (AuzoneAccount.DEBUG) Log.d(TAG, "refreshAccessToken() onResponse token:  " + authTokenResponse.getAccessToken());
                            updateLocalAccount(mAccountManager, account, authTokenResponse);
                            tokenCallback.onTokenReceived(authTokenResponse.getAccessToken());
                        }
                    },
                    new ErrorListener() {
                        @Override
                        public void onErrorResponse(VolleyError volleyError) {
                            mInFlightTokenRequest = null;
                            if (volleyError.networkResponse == null) {
                                if (AuzoneAccount.DEBUG) Log.d(TAG, "refreshAccessToken() onErrorResponse no response");
                                volleyError.printStackTrace();
                                tokenCallback.onError(volleyError);
                                return;
                            }
                            final int status = volleyError.networkResponse.statusCode;

                            if (AuzoneAccount.DEBUG) Log.d(TAG, "refreshAccessToken() onErrorResponse:  " + status);
                            if (status == 401) {
                                Log.d(TAG, "Received 401 response, expiring refresh token.");
                                notifyPasswordChange(account);
                                expireRefreshToken(mAccountManager, account);
                                return;
                            } else {
                                tokenCallback.onError(volleyError);
                            }
                        }
                    });
        } else {
            if (AuzoneAccount.DEBUG) Log.d(TAG, "doTokenRequest() returning cached token : " + currentToken);
            tokenCallback.onTokenReceived(currentToken);
        }
    }

    private String getCarrierName() {
        TelephonyManager manager = (TelephonyManager)mContext.getSystemService(Context.TELEPHONY_SERVICE);
        return manager.getNetworkOperatorName();
    }

    private static String getServerURI() {
        String AuzoneAccountUri = ((AuzoneAccount)AppGlobals.getInitialApplication()).getAuzoneAccountUri();
        String uri = AuzoneAccount.DEBUG ? SystemProperties.get("auzoneaccount.uri") : AuzoneAccountUri;
        String serverUri = (uri == null || uri.length() == 0) ? AuzoneAccountUri : uri;
        if (AuzoneAccount.DEBUG) Log.d(TAG, "Using AuzoneAccount uri:  " + serverUri);
        return serverUri;
    }

    private boolean okToDestroy() {
        String prop = AuzoneAccount.DEBUG ? SystemProperties.get("auzoneaccount.skipwipe") : null;
        boolean skipWipe = (prop == null || prop.length() == 0) ? false : Integer.valueOf(prop) > 0;
        return !skipWipe;
    }

    public void destroyDevice(Context context, String keyId) {
        final PowerManager pm = (PowerManager)context.getSystemService(Context.POWER_SERVICE);
        final PowerManager.WakeLock wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, TAG);
        wakeLock.acquire(1000 * 60);
        final DevicePolicyManager dpm = (DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE);

        // Send a message back to the browser to indicate that the wipe has started.
        final SendChannelRequestBody sendChannelRequestBody = new SendChannelRequestBody(mContext, keyId, new WipeStartedMessage());
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                sendChannel(sendChannelRequestBody,
                new Listener<Integer>() {
                    @Override
                    public void onResponse(Integer integer) {
                        if (AuzoneAccount.DEBUG) Log.d(TAG, "wipeStarted onResponse="+integer);
                    }
                },
                new ErrorListener() {
                    @Override
                    public void onErrorResponse(VolleyError volleyError) {
                        if (AuzoneAccount.DEBUG) Log.d(TAG, "wipeStarted onErrorResponse:");
                        volleyError.printStackTrace();
                    }
                });
                if (okToDestroy()) {
                    if (AuzoneAccount.DEBUG) Log.d(TAG, "Wipe enabled, wiping....");
                    dpm.wipeData(DevicePolicyManager.WIPE_EXTERNAL_STORAGE);
                } else {
                    if (AuzoneAccount.DEBUG) Log.d(TAG, "Skipping wipe");
                }
            }
        });
        t.start();
    }

    public SharedPreferences getAuthPreferences() {
        return mContext.getSharedPreferences(AuzoneAccount.AUTH_PREFERENCES,
                Context.MODE_PRIVATE);
    }

    public SharedPreferences getEncryptionPreferences() {
        return mContext.getSharedPreferences(AuzoneAccount.ENCRYPTION_PREFERENCES, Context.MODE_PRIVATE);
    }

    public boolean isTokenExpired(AccountManager am, Account account) {
        final String expires_in = am.getUserData(account, AuzoneAccount.AUTHTOKEN_EXPIRES_IN);
        long expiresTime = expires_in == null ? 0 : Long.valueOf(expires_in);
        return System.currentTimeMillis() > expiresTime;
    }

    public void expireToken(AccountManager am, Account account) {
        final String token = am.getUserData(account, AuzoneAccount.AUTHTOKEN_TYPE_ACCESS);
        if (!TextUtils.isEmpty(token)) {
            am.invalidateAuthToken(AuzoneAccount.ACCOUNT_TYPE_AuzoneAccount, token);
        }
    }

    public void expireRefreshToken(AccountManager accountManager, Account account) {
        accountManager.clearPassword(account);
    }

    public void notifyPasswordChange(Account account) {
        mAccountManager.updateCredentials(account, AuzoneAccount.ACCOUNT_TYPE_AuzoneAccount, null, null, new AccountManagerCallback<Bundle>() {
            @Override
            public void run(AccountManagerFuture<Bundle> bundleAccountManagerFuture) {
                try {
                    Bundle bundle = bundleAccountManagerFuture.getResult();
                    Intent intent = bundle.getParcelable(AccountManager.KEY_INTENT);
                    PendingIntent contentIntent = PendingIntent.getActivity(mContext, 0,
                            intent, 0);
                    Notification notification = new Notification.Builder(mContext)
                            .setContentTitle(mContext.getText(R.string.auzoneaccount_password_changed_title))
                            .setContentText(mContext.getText(R.string.auzoneaccount_password_changed_message))
                            .setSmallIcon(R.drawable.ic_dialog_alert)
                            .setLargeIcon(((BitmapDrawable) mContext.getResources().getDrawable(R.drawable.icon)).getBitmap())
                            .setContentIntent(contentIntent)
                            .build();
                    AuzoneAccountUtils.showNotification(mContext, AuzoneAccount.NOTIFICATION_ID_PASSWORD_RESET, notification);
                } catch (OperationCanceledException e) {
                    Log.e(TAG, e.toString(), e);
                } catch (IOException e) {
                    Log.e(TAG, e.toString(), e);
                } catch (AuthenticatorException e) {
                    Log.e(TAG, e.toString(), e);
                }
            }
        }, mHandler);
    }

    public void incrementSessionLocalSequence(String keyId) {
        if (AuzoneAccount.DEBUG) Log.d(TAG, "Incrementing local sequence for keyId:" + keyId);
        AuzoneAccountProvider.incrementSequence(mContext, AuzoneAccountProvider.SymmetricKeyStoreColumns.LOCAL_SEQUENCE, keyId);
    }

    public void incrementSessionRemoteSequence(String keyId) {
        if (AuzoneAccount.DEBUG) Log.d(TAG, "Incrementing remote sequence for keyId:" + keyId);
        AuzoneAccountProvider.incrementSequence(mContext, AuzoneAccountProvider.SymmetricKeyStoreColumns.REMOTE_SEQUENCE, keyId);
    }

    public SymmetricKeySequencePair getSymmetricKey(String keyId) {
        if (AuzoneAccount.DEBUG) Log.d(TAG, "Loading symmetric key for keyId:" + keyId);
        // TODO(ctso): keys should expire
        if (keyId == null) {
            return null;
        }
        Cursor c = null;
        try {
            c = mContext.getContentResolver().query(AuzoneAccountProvider.SYMMETRIC_KEY_CONTENT_URI, null, AuzoneAccountProvider.SymmetricKeyStoreColumns.KEY_ID + " = ?", new String[]{keyId}, null);
            if (c != null && c.getCount() > 0) {
                c.moveToFirst();
                String symmetricKey = c.getString(c.getColumnIndex(AuzoneAccountProvider.SymmetricKeyStoreColumns.KEY));
                int localSequence = c.getInt(c.getColumnIndex(AuzoneAccountProvider.SymmetricKeyStoreColumns.LOCAL_SEQUENCE));
                int remoteSequence = c.getInt(c.getColumnIndex(AuzoneAccountProvider.SymmetricKeyStoreColumns.REMOTE_SEQUENCE));
                return new SymmetricKeySequencePair(symmetricKey, localSequence, remoteSequence);
            }
        } finally {
            if (c != null) {
                c.close();
            }
        }

        Log.w(TAG, "Unable to load symmetric key from database for keyId:" + keyId);
        return null;
    }

    public String getUniqueDeviceId() {
        return AuzoneAccountUtils.getUniqueDeviceId(mContext);
    }

    private static interface TokenCallback {
        void onTokenReceived(String token);
        void onError(VolleyError error);
    }

    public static class SymmetricKeySequencePair {
        private String symmetricKey;
        private int localSequence;
        private int remoteSequence;

        public SymmetricKeySequencePair(String symmetricKey, int localSequence, int remoteSequence) {
            this.symmetricKey = symmetricKey;
            this.localSequence = localSequence;
            this.remoteSequence = remoteSequence;
        }

        public String getSymmetricKey() {
            return symmetricKey;
        }

        public int getLocalSequence() {
            return localSequence;
        }

        public int getRemoteSequence() {
            return remoteSequence;
        }
    }

    protected String getRefreshToken(Account account) {
        return mAccountManager.getPassword(account);
    }

    private String generateDeviceSalt(Account account) {
        String salt = EncryptionUtils.generateSaltBase64(16);
        if (AuzoneAccount.DEBUG) Log.v(TAG, "Saving device salt: " + salt);
        mAccountManager.setUserData(account, AuzoneAccount.ACCOUNT_EXTRA_DEVICE_SALT, salt);
        return salt;
    }

    private void generateHmacSecret(Account account, String password, String salt) {
        String hmacSecret = EncryptionUtils.PBKDF2.getDerivedKeyBase64(password, salt);
        if (AuzoneAccount.DEBUG) Log.v(TAG, "Saving hmac secret: " + hmacSecret);
        mAccountManager.setUserData(account, AuzoneAccount.ACCOUNT_EXTRA_HMAC_SECRET, hmacSecret);
    }

    private void generateEncryptionExtras(Account account, String password) {
        String deviceSalt = generateDeviceSalt(account);
        generateHmacSecret(account, password, deviceSalt);
    }
}
