/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.commons.vfs2.provider.http;

import org.apache.commons.httpclient.Cookie;
import org.apache.commons.httpclient.HostConfiguration;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpConnectionManager;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.apache.commons.httpclient.auth.AuthScope;
import org.apache.commons.httpclient.contrib.ssl.AuthSSLProtocolSocketFactory;
import org.apache.commons.httpclient.params.HttpClientParams;
import org.apache.commons.httpclient.params.HttpConnectionManagerParams;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.apache.commons.vfs2.FileSystemException;
import org.apache.commons.vfs2.FileSystemOptions;
import org.apache.commons.vfs2.UserAuthenticationData;
import org.apache.commons.vfs2.UserAuthenticator;
import org.apache.commons.vfs2.util.UserAuthenticatorUtils;

/**
 * Create a HttpClient instance.
 */
public final class HttpClientFactory
{
    private HttpClientFactory()
    {
    }

    public static HttpClient createConnection(final String scheme, final String hostname, final int port,
                                              final String username, final String password,
                                              final FileSystemOptions fileSystemOptions)
            throws FileSystemException
    {
        return createConnection(HttpFileSystemConfigBuilder.getInstance(), scheme, hostname, port,
            username, password, fileSystemOptions);
    }

    /**
     * Creates a new connection to the server.
     * @param builder The HttpFileSystemConfigBuilder.
     * @param scheme The protocol.
     * @param hostname The hostname.
     * @param port The port number.
     * @param username The username.
     * @param password The password
     * @param fileSystemOptions The file system options.
     * @return a new HttpClient connection.
     * @throws FileSystemException if an error occurs.
     * @since 2.0
     */
    public static HttpClient createConnection(final HttpFileSystemConfigBuilder builder, final String scheme,
                                              final String hostname, final int port, final String username,
                                              final String password, final FileSystemOptions fileSystemOptions)
            throws FileSystemException
    {
        HttpClient client;
        try
        {
            final HttpConnectionManager mgr = new MultiThreadedHttpConnectionManager();
            final HttpConnectionManagerParams connectionMgrParams = mgr.getParams();

            client = new HttpClient(mgr);

            final HostConfiguration config = new HostConfiguration();
 
            if (fileSystemOptions != null)
            {
                final String proxyHost = builder.getProxyHost(fileSystemOptions);
                final int proxyPort = builder.getProxyPort(fileSystemOptions);

                if (proxyHost != null && proxyHost.length() > 0 && proxyPort > 0)
                {
                    config.setProxy(proxyHost, proxyPort);
                }

                final UserAuthenticator proxyAuth = builder.getProxyAuthenticator(fileSystemOptions);
                if (proxyAuth != null)
                {
                    final UserAuthenticationData authData = UserAuthenticatorUtils.authenticate(proxyAuth,
                        new UserAuthenticationData.Type[]
                        {
                            UserAuthenticationData.USERNAME,
                            UserAuthenticationData.PASSWORD
                        });

                    if (authData != null)
                    {
                        final UsernamePasswordCredentials proxyCreds =
                            new UsernamePasswordCredentials(
                                UserAuthenticatorUtils.toString(UserAuthenticatorUtils.getData(authData,
                                    UserAuthenticationData.USERNAME, null)),
                                UserAuthenticatorUtils.toString(UserAuthenticatorUtils.getData(authData,
                                    UserAuthenticationData.PASSWORD, null)));

                        final AuthScope scope = new AuthScope(proxyHost, AuthScope.ANY_PORT);
                        client.getState().setProxyCredentials(scope, proxyCreds);
                    }
                }
                
                final HttpClientParams httpClientParams = new HttpClientParams();
                if (builder.isPreemptiveAuth(fileSystemOptions))
                {
                	httpClientParams.setAuthenticationPreemptive(true);
                }
                httpClientParams.setCookiePolicy(builder.getCookiePolicy(fileSystemOptions));
                client.setParams(httpClientParams);

                final Cookie[] cookies = builder.getCookies(fileSystemOptions);
                if (cookies != null)
                {
                    client.getState().addCookies(cookies);
                }
                
                if (scheme.equals("https") && (builder.getKeyStore(fileSystemOptions) != null || builder.getTrustStore(fileSystemOptions) != null)) {
                	ProtocolSocketFactory socketFactory = new AuthSSLProtocolSocketFactory(builder.getKeyStore(fileSystemOptions),
                    		builder.getKeyStorePassword(fileSystemOptions),
                    		builder.getTrustStore(fileSystemOptions),
                    		builder.getTrustStorePassword(fileSystemOptions));
                    Protocol https = new Protocol("https", socketFactory, port);
                    config.setHost(hostname, port, https);                 	
                }
                else {
                    config.setHost(hostname, port, scheme);                	
                }
            }
            else {
            	config.setHost(hostname, port, scheme);                	            	
            }
            
            /**
             * ConnectionManager set methods must be called after the host & port and proxy host & port
             * are set in the HostConfiguration. They are all used as part of the key when HttpConnectionManagerParams
             * tries to locate the host configuration.
             */
            connectionMgrParams.setMaxConnectionsPerHost(config, builder.getMaxConnectionsPerHost(fileSystemOptions));
            connectionMgrParams.setMaxTotalConnections(builder.getMaxTotalConnections(fileSystemOptions));

            connectionMgrParams.setConnectionTimeout(builder.getConnectionTimeout(fileSystemOptions));
            connectionMgrParams.setSoTimeout(builder.getSoTimeout(fileSystemOptions));

            client.setHostConfiguration(config);

            if (username != null)
            {
                final UsernamePasswordCredentials creds =
                    new UsernamePasswordCredentials(username, password);
                final AuthScope scope = new AuthScope(hostname, AuthScope.ANY_PORT);
                client.getState().setCredentials(scope, creds);
            }
        }
        catch (final Exception exc)
        {
            throw new FileSystemException("vfs.provider.http/connect.error", exc, hostname);
        }

        return client;
    }
}
