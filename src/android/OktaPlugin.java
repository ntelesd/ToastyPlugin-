package com.shorteststraw.cordova.plugin;
// The native Toast API
import android.widget.Toast;

import android.content.Context;
// Cordova-required packages
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.okta.oidc.OIDCConfig;
import com.okta.oidc.Okta;
import com.okta.oidc.clients.web.WebAuthClient;
import com.okta.oidc.clients.SyncAuthClient;
import com.okta.oidc.storage.SharedPreferenceStorage;

import android.util.Log;

import com.okta.authn.sdk.client.AuthenticationClient;
import com.okta.authn.sdk.client.AuthenticationClients;
import com.okta.authn.sdk.AuthenticationException;
import com.okta.authn.sdk.AuthenticationStateHandlerAdapter;
import com.okta.authn.sdk.resource.AuthenticationResponse;

import com.okta.oidc.AuthorizationStatus;
import com.okta.oidc.RequestCallback;
import com.okta.oidc.ResultCallback;
import com.okta.oidc.results.Result;
import com.okta.oidc.Tokens;
import com.okta.oidc.clients.sessions.SessionClient;
import com.okta.oidc.net.response.UserInfo;
import com.okta.oidc.storage.security.DefaultEncryptionManager;
import com.okta.oidc.storage.security.EncryptionManager;
import com.okta.oidc.storage.security.GuardedEncryptionManager;
import com.okta.oidc.util.AuthorizationException;
import com.okta.oidc.net.OktaHttpClient;

import androidx.annotation.NonNull;

import java.util.concurrent.Executors;


public class OktaPlugin extends CordovaPlugin {
    private OIDCConfig config;
    private WebAuthClient client;
    private Context context;
    private PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, "Just initialized");
    private AuthenticationClient authenticationClient;
    private SyncAuthClient mAuthClient;
    private EncryptionManager mEncryptionManager;

    @Override
    public boolean execute(String action, final JSONArray args, final CallbackContext callbackContext) {
        context = this.cordova.getActivity().getApplicationContext();

        // Verify that a 'InitializePlugin' action was sent
        if (action.equals("InitializePlugin")) {
            try {
                config = new OIDCConfig.Builder()
                        .clientId("0oal19297i0RZZO4A5d6")
                        .redirectUri("com.shorteststraw.okta:/callback")
                        .endSessionRedirectUri("com.shorteststraw.okta:/logout")
                        .scopes("openid", "profile", "offline_access")
                        .discoveryUri("https://dev-62426961.okta.com/")
                        .create();

                //if (InitializePlugin()) {
                // Send a positive result to the callbackContext
                PluginResult pluginResult = new PluginResult(PluginResult.Status.OK);
                pluginResult.setKeepCallback(true);
                callbackContext.sendPluginResult(pluginResult);
                return true;
                //}
            } catch (Exception e) {
                callbackContext.error("Error encountered: " + e.getMessage());
                return false;
            }
        }

        if (action.equals("webAuthClient")) {
            try {
                pluginResult = new PluginResult(PluginResult.Status.OK, "client auth start");
                config = new OIDCConfig.Builder()
                        .clientId("0oal19297i0RZZO4A5d6")
                        .redirectUri("com.shorteststraw.okta:/callback")
                        .endSessionRedirectUri("com.shorteststraw.okta:/logout")
                        .scopes("openid", "profile", "offline_access")
                        .discoveryUri("https://dev-62426961.okta.com/")
                        .create();
                pluginResult = new PluginResult(PluginResult.Status.OK, "get context");
                pluginResult = new PluginResult(PluginResult.Status.OK, "build client");
                WebAuthClient client = new Okta.WebAuthBuilder()
                        .withConfig(config)
                        .withContext(context)
                        .withStorage(new SharedPreferenceStorage(context))
                        .withCallbackExecutor(Executors.newSingleThreadExecutor())
                        .supportedBrowsers("com.android.chrome", "org.mozilla.firefox")
                        .create();
                pluginResult = new PluginResult(PluginResult.Status.OK, "get session client");
                final SessionClient sessionClient = client.getSessionClient();
                pluginResult = new PluginResult(PluginResult.Status.OK, "register callback");
                client.registerCallback(new ResultCallback<AuthorizationStatus, AuthorizationException>() {
                    @Override
                    public void onSuccess(@NonNull AuthorizationStatus status) {
                        if (status == AuthorizationStatus.AUTHORIZED) {
                            //client is authorized.
                            try{
                                Tokens tokens = sessionClient.getTokens();
                            } catch (AuthorizationException exception) {
                                pluginResult = new PluginResult(PluginResult.Status.OK, "Error getTokens");
                            }

                            pluginResult = new PluginResult(PluginResult.Status.OK, "Client is authorized");
                        } else if (status == AuthorizationStatus.SIGNED_OUT) {
                            //this only clears the browser session.
                            pluginResult = new PluginResult(PluginResult.Status.OK, "Client is signed out");
                        }
                    }

                    @Override
                    public void onCancel() {
                        //authorization canceled
                        pluginResult = new PluginResult(PluginResult.Status.OK, "Canceled");
                    }

                    @Override
                    public void onError(@NonNull String msg, AuthorizationException error) {
                        //error encounted
                        pluginResult = new PluginResult(PluginResult.Status.OK, "Encontered error: " + msg);
                    }
                }, this.cordova.getActivity());

                pluginResult = new PluginResult(PluginResult.Status.OK, "client sign in start");

                client.signIn(this.cordova.getActivity(), null);

                pluginResult = new PluginResult(PluginResult.Status.OK, "client sign in requested");

                // Send a positive result to the callbackContext
                //pluginResult = new PluginResult(PluginResult.Status.OK, );
                pluginResult.setKeepCallback(true);
                callbackContext.sendPluginResult(pluginResult);
                return true;
                //}
            } catch (Exception e) {
                callbackContext.error("Error encountered: " + e.getMessage());
                return false;
            }
        }

        if (action.equals("authClient")) {
            pluginResult = new PluginResult(PluginResult.Status.OK, "Auth client action");
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    //pluginResult = new PluginResult(PluginResult.Status.OK, "thread run");
                    Log.d("AuthClient", "thread run");
                    try {
                        //pluginResult = new PluginResult(PluginResult.Status.OK, "original context");
                        Log.d("AuthClient", "original context");
                        ClassLoader originalClassLoader = Thread.currentThread().getContextClassLoader();
                        try {
                            //pluginResult = new PluginResult(PluginResult.Status.OK, "trying to change context");
                            Log.d("AuthClient", "trying to change context");
                            Thread.currentThread().setContextClassLoader(getClass().getClassLoader());
                            //pluginResult = new PluginResult(PluginResult.Status.OK, "build authentication client");
                            Log.d("AuthClient", "build authentication client");
                            authenticationClient = AuthenticationClients.builder()
                                    .setOrgUrl("https://dev-62426961.okta.com")
                                    .build();
                        } finally {
                            //pluginResult = new PluginResult(PluginResult.Status.OK, "set original context");
                            Log.d("AuthClient", "set original context");
                            Thread.currentThread().setContextClassLoader(originalClassLoader);
                        }

                        /*authenticationClient = AuthenticationClients.builder()
                                .setOrgUrl("https://dev-62426961.okta.com")
                                .build();*/
                        //pluginResult = new PluginResult(PluginResult.Status.OK, "authenticating");
                        Log.d("AuthClient", "authenticating");
                        String user = args.optString(0);
                        String pass = args.optString(1);
                        Log.d("AuthClient", "user: " + user + " | pass: " + pass);
                        //authenticationClient.authenticate("nun0_dias@hotmail.com", pass.toCharArray(), null, new AuthenticationStateHandlerAdapter() {
                        authenticationClient.authenticate(user, pass.toCharArray(), null, new AuthenticationStateHandlerAdapter() {
                            @Override
                            public void handleUnknown(AuthenticationResponse authenticationResponse) {
                                Log.d("AuthClient", "Unknow");
                                pluginResult = new PluginResult(PluginResult.Status.OK, "Unknow");
                                callbackContext.sendPluginResult(pluginResult);
                            }

                            @Override
                            public void handleLockedOut(AuthenticationResponse lockedOut) {
                                Log.d("AuthClient", "Locked Out");
                                pluginResult = new PluginResult(PluginResult.Status.OK, "Locked Out");
                                callbackContext.sendPluginResult(pluginResult);
                            }

                            @Override
                            public void handleSuccess(AuthenticationResponse successResponse) {
                                //pluginResult = new PluginResult(PluginResult.Status.OK, "Client authenticate success");
                                Log.d("AuthClient", "Client authenticate success");
                                String sessionToken = successResponse.getSessionToken();
                                mAuthClient = provideAuthClient(context);
                                Result res = mAuthClient.signIn(sessionToken, null);
                                if (res.isSuccess()) {
                                    Log.d("AuthClient", "Success sign in");
                                    pluginResult = new PluginResult(PluginResult.Status.OK, "Success sign in");
                                    callbackContext.sendPluginResult(pluginResult);
                                } else {
                                    Log.d("AuthClient", "Authorization exception: " + res.getError().getLocalizedMessage());
                                    pluginResult = new PluginResult(PluginResult.Status.OK, "Authorization exception: " + res.getError().getLocalizedMessage());
                                    callbackContext.sendPluginResult(pluginResult);
                                }
                            }
                        });
                    } catch (AuthenticationException e) {
                        Log.d("AuthClient", "Authentication exception: " + Log.getStackTraceString(e));
                        pluginResult = new PluginResult(PluginResult.Status.OK, "Authentication exception: " + Log.getStackTraceString(e));
                        callbackContext.sendPluginResult(pluginResult);
                    }
                }
            });
            Log.d("AuthClient", "Auth client ended");
            return true;
        }

        if (action.equals("asyncAuthClient")) {
            try {
                synchronized (OktaPlugin.class) {
                    authenticationClient = AuthenticationClients.builder()
                            .setOrgUrl("https://dev-62426961.okta.com")
                            .build();
                    String pass = "okta@dmin001";
                    authenticationClient.authenticate("ntelesd@gmail.com", pass.toCharArray(), null, new AuthenticationStateHandlerAdapter() {
                        @Override
                        public void handleUnknown(AuthenticationResponse authenticationResponse) {
                            pluginResult = new PluginResult(PluginResult.Status.OK, "Unknow");
                        }

                        @Override
                        public void handleLockedOut(AuthenticationResponse lockedOut) {
                            pluginResult = new PluginResult(PluginResult.Status.OK, "Locked Out");
                        }

                        @Override
                        public void handleSuccess(AuthenticationResponse successResponse) {
                            String sessionToken = successResponse.getSessionToken();
                            mAuthClient = provideAuthClient(context);
                            Result res = mAuthClient.signIn(sessionToken, null);
                            if (res.isSuccess()) {
                                pluginResult = new PluginResult(PluginResult.Status.OK, "Success sign in");
                            }
                            else {
                                pluginResult = new PluginResult(PluginResult.Status.OK, "Authorization exception: " + res.getError().getLocalizedMessage());
                            }
                        }
                    });
                }
            } catch (AuthenticationException e) {
                pluginResult = new PluginResult(PluginResult.Status.OK, "Log: " + Log.getStackTraceString(e));
            }
        }

        if (action.equals("signIn")) {
            try {
                pluginResult = new PluginResult(PluginResult.Status.OK, "client sign in start");

                client.signIn(this.cordova.getActivity(), null);

                pluginResult = new PluginResult(PluginResult.Status.OK, "client sign in requested");
                // Send a positive result to the callbackContext
                //pluginResult = new PluginResult(PluginResult.Status.OK, );
                pluginResult.setKeepCallback(true);
                callbackContext.sendPluginResult(pluginResult);
                return true;
                //}
            } catch (Exception e) {
                callbackContext.error("Error encountered: " + e.getMessage());
                return false;
            }
        }


        callbackContext.error("\"" + action + "\" is not a recognized action.");
        return false;
    }

    private SyncAuthClient provideAuthClient(Context context) {
        SyncAuthClient localAuth = mAuthClient;
        if(localAuth == null) {
            synchronized (OktaPlugin.class) {
                localAuth = mAuthClient;
                if(localAuth == null) {
                    /*OIDCConfig mOidcConfig = new OIDCConfig.Builder()
                            .withJsonFile(context, "..\\res\\raw\\okta_oidc_config.json")
                            .create();*/

                    OIDCConfig config = new OIDCConfig.Builder()
                            .clientId("0oal19297i0RZZO4A5d6")
                            .redirectUri("com.shorteststraw.okta:/callback")
                            .endSessionRedirectUri("com.shorteststraw.okta:/logout")
                            .scopes("openid", "profile", "offline_access")
                            .discoveryUri("https://dev-62426961.okta.com/")
                            .create();

                    //boolean isSmartLockEncryptionManager = providePreferenceRepository(context).isEnabledSmartLock();

//                    mEncryptionManager = (isSmartLockEncryptionManager) ?
//                            createGuardedEncryptionManager(context) : createSimpleEncryptionManager(context);

//                    mAuth = localAuth = new Okta.AuthBuilder()
//                            .withConfig(mOidcConfig)
//                            .withContext(context.getApplicationContext())
//                            .withStorage(new SharedPreferenceStorage(context))
//                            .setCacheMode(false)
//                            .setRequireHardwareBackedKeyStore(false)
//                            .withEncryptionManager(mEncryptionManager)
//                            .create();

                    mAuthClient = localAuth = new Okta.SyncAuthBuilder()
                            .withConfig(config)
                            .withContext(context)
                            .withStorage(new SharedPreferenceStorage(context))
                            .create();
                }
            }
        }

        return localAuth;
    }

}