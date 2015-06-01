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

import com.android.volley.VolleyError;
import com.auzone.account.AuzoneAccount;
import com.auzone.account.R;
import com.auzone.account.api.AuthTokenResponse;
import com.auzone.account.ui.AuzoneAccountActivity;

import android.accounts.AbstractAccountAuthenticator;
import android.accounts.Account;
import android.accounts.AccountAuthenticatorResponse;
import android.accounts.AccountManager;
import android.accounts.NetworkErrorException;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.text.TextUtils;
import android.util.Log;
import android.widget.Toast;


public class Authenticator extends AbstractAccountAuthenticator {

    private static final String TAG = Authenticator.class.getSimpleName();
    private final Context mContext;
    private AuthClient mAuthClient;
    private AccountManager mAccountManager;

    private final Handler mHandler = new Handler();

    public Authenticator(Context context) {
        super(context);
        mContext = context;
        mAuthClient = AuthClient.getInstance(context);
        mAccountManager = AccountManager.get(mContext);
    }

    @Override
    public Bundle addAccount(AccountAuthenticatorResponse response, String accountType,
                             String authTokenType, String[] requiredFeatures, Bundle options) throws NetworkErrorException {
        if (AuzoneAccount.DEBUG) Log.d(TAG, "addAccount()");
        int accounts = mAccountManager.getAccountsByType(accountType).length;
        final Bundle bundle = new Bundle();
        if (accounts > 0) {
            final String error = mContext.getString(R.string.auzoneaccount_error_multiple_accounts);
            bundle.putInt(AccountManager.KEY_ERROR_CODE, AccountManager.ERROR_CODE_UNSUPPORTED_OPERATION);
            bundle.putString(AccountManager.KEY_ERROR_MESSAGE, error);
            mHandler.post(new Runnable() {
                @Override
                public void run() {
                    Toast.makeText(mContext, error, Toast.LENGTH_SHORT).show();
                }
            });
            return bundle;
        } else {
            final Intent intent = new Intent(mContext, AuzoneAccountActivity.class);
            intent.putExtra(AccountManager.KEY_ACCOUNT_TYPE, AuzoneAccount.ACCOUNT_TYPE_AuzoneAccount);
            intent.putExtra(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE, response);
            intent.putExtra(AuzoneAccount.EXTRA_SHOW_BUTTON_BAR,
                    options.getBoolean(AuzoneAccount.EXTRA_SHOW_BUTTON_BAR, false));
            intent.putExtra(AuzoneAccount.EXTRA_USE_IMMERSIVE,
                    options.getBoolean(AuzoneAccount.EXTRA_USE_IMMERSIVE, false));
            intent.putExtra(AuzoneAccount.EXTRA_FIRST_RUN,
                    options.getBoolean(AuzoneAccount.EXTRA_FIRST_RUN, false));
            bundle.putParcelable(AccountManager.KEY_INTENT, intent);
            return bundle;
        }
    }

    @Override
    public Bundle editProperties(AccountAuthenticatorResponse response, String accountType) {
        return null;
    }

    @Override
    public Bundle confirmCredentials(AccountAuthenticatorResponse response, Account account, Bundle options) throws NetworkErrorException {
        return null;
    }

    @Override
    public Bundle getAuthToken(AccountAuthenticatorResponse response, Account account, String authTokenType, Bundle loginOptions) throws NetworkErrorException {
        if (AuzoneAccount.DEBUG) Log.d(TAG, "getAuthToken() account="+account.name+ " type="+account.type);
        if (!authTokenType.equals(AuzoneAccount.AUTHTOKEN_TYPE_ACCESS)) {
            final Bundle result = new Bundle();
            result.putString(AccountManager.KEY_ERROR_MESSAGE, "invalid authTokenType");
            return result;
        }
        if (hasRefreshToken(account)) {
            if (AuzoneAccount.DEBUG) Log.d(TAG, "refreshing token... account="+account.name+ " type="+account.type);
            Bundle bundle = refreshToken(mAccountManager, account, response);
            if (bundle != null) {
                return bundle;
            }
            return bundle;
        }

        final Bundle result = new Bundle();
        final Intent intent = new Intent(mContext, AuthActivity.class);
        intent.putExtra(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE, response);
        result.putParcelable(AccountManager.KEY_INTENT, intent);
        return result;
    }

    @Override
    public String getAuthTokenLabel(String authTokenType) {
        return null;
    }

    @Override
    public Bundle updateCredentials(AccountAuthenticatorResponse response, Account account, String authTokenType, Bundle loginOptions) throws NetworkErrorException {
        final Bundle result = new Bundle();
        final Intent intent = new Intent(mContext, AuthActivity.class);
        intent.putExtra(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE, response);
        result.putParcelable(AccountManager.KEY_INTENT, intent);
        return result;
    }

    @Override
    public Bundle hasFeatures(AccountAuthenticatorResponse response, Account account, String[] features) throws NetworkErrorException {
        final Bundle result = new Bundle();
        result.putBoolean(AccountManager.KEY_BOOLEAN_RESULT, false);
        return result;
    }

    private Bundle refreshToken(AccountManager am, Account account, AccountAuthenticatorResponse response) {
        final String refreshToken = mAuthClient.getRefreshToken(account);
        if (!TextUtils.isEmpty(refreshToken)) {
            try {
                AuthTokenResponse authResponse = mAuthClient.blockingRefreshAccessToken(refreshToken);
                mAuthClient.updateLocalAccount(am, account, authResponse);
                final String token = authResponse.getAccessToken();
                if (!TextUtils.isEmpty(token)) {
                    final Bundle result = new Bundle();
                    result.putParcelable(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE, response);
                    result.putString(AccountManager.KEY_AUTHTOKEN, token);
                    result.putString(AccountManager.KEY_ACCOUNT_NAME, account.name);
                    result.putString(AccountManager.KEY_ACCOUNT_TYPE, AuzoneAccount.ACCOUNT_TYPE_AuzoneAccount);
                    am.setAuthToken(account, AuzoneAccount.AUTHTOKEN_TYPE_ACCESS, token);
                    return result;
                }
            } catch (VolleyError volleyError) {
                volleyError.printStackTrace();
                final int status = volleyError.networkResponse.statusCode;
                if (status == 400 || status == 401) {
                    mAccountManager.clearPassword(account);
                }
            }
        }
        return null;
    }

    private boolean hasRefreshToken(Account account) {
        return mAuthClient.getRefreshToken(account) != null;
    }
}
