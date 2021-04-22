/*
 * Copyright (c) 2019, Okta, Inc. and/or its affiliates. All rights reserved.
 * The Okta software accompanied by this notice is provided pursuant to the Apache License,
 * Version 2.0 (the "License.")
 *
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the
 * License.
 */
package com.shorteststraw.cordova.plugin;

import android.content.Context;

import com.shorteststraw.cordova.plugin.PreferenceRepository;
/*import com.okta.android.samples.custom_sign_in.util.SmartLockHelper;*/
import com.okta.oidc.OIDCConfig;
import com.okta.oidc.Okta;
import com.okta.oidc.clients.AuthClient;
import com.okta.oidc.storage.SharedPreferenceStorage;

import com.shorteststraw.cordova.plugin.rx_client.RxOkta;
import com.shorteststraw.cordova.plugin.rx_client.RxAuthClient;
import com.okta.oidc.storage.security.DefaultEncryptionManager;
import com.okta.oidc.storage.security.EncryptionManager;
import com.okta.oidc.storage.security.GuardedEncryptionManager;

public class ServiceLocator {
    private static volatile AuthClient mAuth;
    private static volatile RxAuthClient mRxAuth;
    private static volatile EncryptionManager mEncryptionManager;
    private static volatile PreferenceRepository mPreferenceRepository;

    public static AuthClient provideAuthClient(Context context) {
        AuthClient localAuth = mAuth;
        if(localAuth == null) {
            synchronized (ServiceLocator.class) {
                localAuth = mAuth;
                if(localAuth == null) {
                    OIDCConfig mOidcConfig = new OIDCConfig.Builder()
                            .withJsonFile(context, "..\\res\\raw\\okta_oidc_config.json")
                            .create();

                    /*boolean isSmartLockEncryptionManager = providePreferenceRepository(context).isEnabledSmartLock();

                    mEncryptionManager = (isSmartLockEncryptionManager) ?
                            createGuardedEncryptionManager(context) : createSimpleEncryptionManager(context);*/

                    mAuth = localAuth = new Okta.AuthBuilder()
                            .withConfig(mOidcConfig)
                            .withContext(context.getApplicationContext())
                            .withStorage(new SharedPreferenceStorage(context))
                            .setCacheMode(false)
                            .setRequireHardwareBackedKeyStore(false)
                            .withEncryptionManager(mEncryptionManager)
                            .create();
                }
            }
        }

        return localAuth;
    }

    public static PreferenceRepository providePreferenceRepository(Context context) {
        if(mPreferenceRepository == null) {
            mPreferenceRepository = new PreferenceRepository(context);
        }
        return mPreferenceRepository;
    }

    public static GuardedEncryptionManager createGuardedEncryptionManager(Context context) {
        return new GuardedEncryptionManager(context, 10);
    }

    public static DefaultEncryptionManager createSimpleEncryptionManager(Context context) {
        return new DefaultEncryptionManager(context);
    }

    public static EncryptionManager provideEncryptionManager(Context context) {
        return mEncryptionManager;
    }

    public static void setEncryptionManager(EncryptionManager encryptionManager) {
        mEncryptionManager = encryptionManager;
    }

    /*public static SmartLockHelper provideSmartLockHelper() {
        return new SmartLockHelper();
    }*/

    public static RxAuthClient provideRxAuthClient(Context context) {
        RxAuthClient localAuth = mRxAuth;
        if(localAuth == null) {
            synchronized (ServiceLocator.class) {
                localAuth = mRxAuth;
                if (localAuth == null) {
                    OIDCConfig mOidcConfig = new OIDCConfig.Builder()
                            .withJsonFile(context, "..\\res\\raw\\okta_oidc_config.json")
                            .create();

                    mRxAuth = localAuth = new RxOkta.AuthBuilder()
                            .withConfig(mOidcConfig)
                            .withContext(context)
                            .withStorage(new SharedPreferenceStorage(context))
                            .create();
                }
            }
        }
        return localAuth;
    }
}
