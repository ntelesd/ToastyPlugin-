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

package com.shorteststraw.cordova.plugin.rx_client;

import androidx.annotation.ColorInt;

import com.okta.oidc.OktaBuilder;

/**
 * A collection of builders for creating different type of authentication clients.
 * {@link RxAuthClient}
 */
public class RxOkta {
    /**
     * The RX authentication client builder.
     */
    public static class AuthBuilder extends OktaBuilder<RxAuthClient, AuthBuilder> {
        @Override
        protected AuthBuilder toThis() {
            return this;
        }

        /**
         * Create AuthClient.
         *
         * @return the authenticate client {@link RxAuthClient}
         */
        @Override
        public RxAuthClient create() {
            super.withAuthenticationClientFactory(RxAuthClientImpl::new);
            return createAuthClient();
        }
    }

}
