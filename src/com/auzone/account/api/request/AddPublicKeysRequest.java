/*
 * Copyright (C) 2013 The Auzone Project
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

package com.auzone.account.api.request;

import android.util.Log;
import com.android.volley.NetworkResponse;
import com.android.volley.Response;
import com.android.volley.VolleyError;
import com.auzone.account.AuzoneAccount;
import com.auzone.account.api.AuzoneAccountJsonRequest;
import com.auzone.account.api.response.AddPublicKeysResponse;
import com.auzone.account.auth.AuthClient;
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;

public class AddPublicKeysRequest extends AuzoneAccountJsonRequest<AddPublicKeysResponse> {
    private static final String TAG = AddPublicKeysRequest.class.getSimpleName();

    public AddPublicKeysRequest(String authToken, String message, Response.Listener<AddPublicKeysResponse> listener,
                                Response.ErrorListener errorListener) {
        super(AuthClient.ADD_PUBLIC_KEYS_URI, message, listener, errorListener);
        addHeader(PARAM_AUTHORIZATION, "OAuth " + authToken);
    }

    @Override
    protected Response<AddPublicKeysResponse> parseNetworkResponse(NetworkResponse response) {
        String jsonResponse = new String(response.data);
        if (AuzoneAccount.DEBUG) Log.d(TAG, "response code=" + response.statusCode);
        if (AuzoneAccount.DEBUG) Log.d(TAG, "response content = " + jsonResponse);
        try {
            AddPublicKeysResponse res = new Gson().fromJson(jsonResponse, AddPublicKeysResponse.class);
            res.statusCode = response.statusCode;
            return Response.success(res, getCacheEntry());
        } catch (JsonSyntaxException e) {
            return Response.error(new VolleyError(e));
        }
    }
}
