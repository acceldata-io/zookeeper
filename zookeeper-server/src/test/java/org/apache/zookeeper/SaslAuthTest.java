/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.zookeeper;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.apache.zookeeper.ClientCnxn.EventThread;
import org.apache.zookeeper.ClientCnxn.SendThread;
import org.apache.zookeeper.Watcher.Event.KeeperState;
import org.apache.zookeeper.ZooDefs.Ids;
import org.apache.zookeeper.client.ZooKeeperSaslClient;
import org.apache.zookeeper.data.ACL;
import org.apache.zookeeper.data.Id;
import org.apache.zookeeper.test.SaslAuthDigestTestBase;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class SaslAuthTest extends SaslAuthDigestTestBase {

    @BeforeAll
    public static void init() {
        System.setProperty("zookeeper.authProvider.1", "org.apache.zookeeper.server.auth.SASLAuthenticationProvider");
        try {
            File tmpDir = createTmpDir();
            File saslConfFile = new File(tmpDir, "jaas.conf");
            String jaasContent = getJaasFileContent();
            FileWriter fwriter = new FileWriter(saslConfFile);
            fwriter.write(jaasContent);
            fwriter.close();
            System.setProperty("java.security.auth.login.config", saslConfFile.getAbsolutePath());
        } catch (IOException e) {
            // could not create tmp directory to hold JAAS conf file : test will
            // fail now.
        }
    }

    private static String getJaasFileContent() {
        StringBuilder jaasContent = new StringBuilder();
        String newLine = System.getProperty("line.separator");
        jaasContent.append("Server {");
        jaasContent.append(newLine);
        jaasContent.append("org.apache.zookeeper.server.auth.DigestLoginModule required");
        jaasContent.append(newLine);
        jaasContent.append("user_super=\"test\";");
        jaasContent.append(newLine);
        jaasContent.append("};");
        jaasContent.append(newLine);
        jaasContent.append("Client {");
        jaasContent.append(newLine);
        jaasContent.append("org.apache.zookeeper.server.auth.DigestLoginModule required");
        jaasContent.append(newLine);
        jaasContent.append("username=\"super\"");
        jaasContent.append(newLine);
        jaasContent.append("password=\"test\";");
        jaasContent.append(newLine);
        jaasContent.append("};");
        jaasContent.append(newLine);
        return jaasContent.toString();
    }

    @AfterAll
    public static void clean() {
        System.clearProperty("zookeeper.authProvider.1");
        System.clearProperty("java.security.auth.login.config");
    }

    private final CountDownLatch authFailed = new CountDownLatch(1);

    @Override
    protected TestableZooKeeper createClient(String hp) throws IOException, InterruptedException {
        MyWatcher watcher = new MyWatcher();
        return createClient(watcher, hp);
    }

    private class MyWatcher extends CountdownWatcher {

        @Override
        public synchronized void process(WatchedEvent event) {
            if (event.getState() == KeeperState.AuthFailed) {
                authFailed.countDown();
            } else {
                super.process(event);
            }
        }

    }

    @Test
    public void testAuth() throws Exception {
        ZooKeeper zk = createClient();
        try {
            zk.create("/path1", null, Ids.CREATOR_ALL_ACL, CreateMode.PERSISTENT);
            Thread.sleep(1000);
        } finally {
            zk.close();
        }
    }

    @Test
    public void testValidSaslIds() throws Exception {
        ZooKeeper zk = createClient();

        List<String> validIds = new ArrayList<String>();
        validIds.add("user");
        validIds.add("service/host.name.com");
        validIds.add("user@KERB.REALM");
        validIds.add("service/host.name.com@KERB.REALM");

        int i = 0;
        for (String validId : validIds) {
            List<ACL> aclList = new ArrayList<ACL>();
            ACL acl = new ACL(0, new Id("sasl", validId));
            aclList.add(acl);
            zk.create("/valid" + i, null, aclList, CreateMode.PERSISTENT);
            i++;
        }
    }

    @Test
    public void testInvalidSaslIds() throws Exception {
        ZooKeeper zk = createClient();

        List<String> invalidIds = new ArrayList<String>();
        invalidIds.add("user@KERB.REALM/server.com");
        invalidIds.add("user@KERB.REALM1@KERB.REALM2");

        int i = 0;
        for (String invalidId : invalidIds) {
            List<ACL> aclList = new ArrayList<ACL>();
            try {
                ACL acl = new ACL(0, new Id("sasl", invalidId));
                aclList.add(acl);
                zk.create("/invalid" + i, null, aclList, CreateMode.PERSISTENT);
                fail("SASLAuthenticationProvider.isValid() failed to catch invalid Id.");
            } catch (KeeperException.InvalidACLException e) {
                // ok.
            } finally {
                i++;
            }
        }
    }

    @Test
    public void testZKOperationsAfterClientSaslAuthFailure() throws Exception {
        CountdownWatcher watcher = new CountdownWatcher();
        ZooKeeper zk = new ZooKeeper(hostPort, CONNECTION_TIMEOUT, watcher);
        watcher.waitForConnected(CONNECTION_TIMEOUT);
        try {
            setSaslFailureFlag(zk);

            // try node creation for around 15 second,
            int totalTry = 10;
            int tryCount = 0;

            boolean success = false;
            while (!success && tryCount++ <= totalTry) {
                try {
                    zk.create("/saslAuthFail", "data".getBytes(), Ids.OPEN_ACL_UNSAFE, CreateMode.PERSISTENT_SEQUENTIAL);
                    success = true;
                } catch (KeeperException.ConnectionLossException e) {
                    Thread.sleep(1000);
                    // do nothing
                }
            }
            assertTrue(success, "ZNode creation is failing continuously after Sasl auth failure.");

        } finally {
            zk.close();
        }
    }

    // set saslLoginFailed to true to simulate the LoginException
    private void setSaslFailureFlag(ZooKeeper zk) throws Exception {
        Field cnxnField = zk.getClass().getDeclaredField("cnxn");
        cnxnField.setAccessible(true);
        ClientCnxn clientCnxn = (ClientCnxn) cnxnField.get(zk);
        Field sendThreadField = clientCnxn.getClass().getDeclaredField("sendThread");
        sendThreadField.setAccessible(true);
        SendThread sendThread = (SendThread) sendThreadField.get(clientCnxn);
        Field saslLoginFailedField = sendThread.getClass().getDeclaredField("saslLoginFailed");
        saslLoginFailedField.setAccessible(true);
        saslLoginFailedField.setBoolean(sendThread, true);
    }

    @Test
    public void testThreadsShutdownOnAuthFailed() throws Exception {
        MyWatcher watcher = new MyWatcher();
        ZooKeeper zk = null;
        try {
            zk = new ZooKeeper(hostPort, CONNECTION_TIMEOUT, watcher);
            watcher.waitForConnected(CONNECTION_TIMEOUT);
            try {
                zk.addAuthInfo("FOO", "BAR".getBytes());
                zk.getData("/path1", false, null);
                fail("Should get auth state error");
            } catch (KeeperException.AuthFailedException e) {
                if (!authFailed.await(CONNECTION_TIMEOUT, TimeUnit.MILLISECONDS)) {
                    fail("Should have called my watcher");
                }
            }
            Field cnxnField = zk.getClass().getDeclaredField("cnxn");
            cnxnField.setAccessible(true);
            ClientCnxn clientCnxn = (ClientCnxn) cnxnField.get(zk);
            Field sendThreadField = clientCnxn.getClass().getDeclaredField("sendThread");
            sendThreadField.setAccessible(true);
            SendThread sendThread = (SendThread) sendThreadField.get(clientCnxn);
            Field eventThreadField = clientCnxn.getClass().getDeclaredField("eventThread");
            eventThreadField.setAccessible(true);
            EventThread eventThread = (EventThread) eventThreadField.get(clientCnxn);
            ZooKeeperSaslClient zooKeeperSaslClient = clientCnxn.getZooKeeperSaslClient();
            assertNotNull(zooKeeperSaslClient);
            sendThread.join(CONNECTION_TIMEOUT);
            eventThread.join(CONNECTION_TIMEOUT);
            // If login is null, this means ZooKeeperSaslClient#shutdown method has been called which in turns
            // means that Login#shutdown has been called.
            assertNull(sendThread.getLogin());
            assertFalse(sendThread.isAlive(), "SendThread did not shutdown after authFail");
            assertFalse(eventThread.isAlive(), "EventThread did not shutdown after authFail");
        } finally {
            if (zk != null) {
                zk.close();
            }
        }
    }

    @Test
    public void testDisconnectNotCreatingLoginThread() throws Exception {
        MyWatcher watcher = new MyWatcher();
        ZooKeeper zk = null;
        try {
            zk = new ZooKeeper(hostPort, CONNECTION_TIMEOUT, watcher);
            watcher.waitForConnected(CONNECTION_TIMEOUT);
            zk.getData("/", false, null);

            Field cnxnField = zk.getClass().getDeclaredField("cnxn");
            cnxnField.setAccessible(true);
            ClientCnxn clientCnxn = (ClientCnxn) cnxnField.get(zk);
            Field sendThreadField = clientCnxn.getClass().getDeclaredField("sendThread");
            sendThreadField.setAccessible(true);
            SendThread sendThread = (SendThread) sendThreadField.get(clientCnxn);

            Login l1 = sendThread.getLogin();
            assertNotNull(l1);

            stopServer();
            watcher.waitForDisconnected(CONNECTION_TIMEOUT);
            startServer();
            watcher.waitForConnected(CONNECTION_TIMEOUT);
            zk.getData("/", false, null);

            assertSame("Login thread should not been recreated on disconnect", l1, sendThread.getLogin());
        } finally {
            if (zk != null) {
                zk.close();
            }
        }
    }
}
