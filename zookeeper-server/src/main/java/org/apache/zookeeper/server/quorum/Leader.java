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

package org.apache.zookeeper.server.quorum;

import static java.nio.charset.StandardCharsets.UTF_8;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;
import javax.security.sasl.SaslException;
import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.ZooDefs.OpCode;
import org.apache.zookeeper.common.Time;
import org.apache.zookeeper.jmx.MBeanRegistry;
import org.apache.zookeeper.server.ExitCode;
import org.apache.zookeeper.server.FinalRequestProcessor;
import org.apache.zookeeper.server.Request;
import org.apache.zookeeper.server.RequestProcessor;
import org.apache.zookeeper.server.ServerMetrics;
import org.apache.zookeeper.server.ZKDatabase;
import org.apache.zookeeper.server.ZooKeeperCriticalThread;
import org.apache.zookeeper.server.ZooTrace;
import org.apache.zookeeper.server.quorum.QuorumPeer.LearnerType;
import org.apache.zookeeper.server.quorum.auth.QuorumAuthServer;
import org.apache.zookeeper.server.quorum.flexible.QuorumVerifier;
import org.apache.zookeeper.server.util.ZxidUtils;
import org.apache.zookeeper.util.ServiceUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class has the control logic for the Leader.
 */
public class Leader extends LearnerMaster {

    private static final Logger LOG = LoggerFactory.getLogger(Leader.class);

    private static final boolean nodelay = System.getProperty("leader.nodelay", "true").equals("true");

    static {
        LOG.info("TCP NoDelay set to: {}", nodelay);
    }

    public static class Proposal extends SyncedLearnerTracker {

        public QuorumPacket packet;
        public Request request;

        @Override
        public String toString() {
            return packet.getType() + ", " + packet.getZxid() + ", " + request;
        }

    }

    // log ack latency if zxid is a multiple of ackLoggingFrequency. If <=0, disable logging.
    private static final String ACK_LOGGING_FREQUENCY = "zookeeper.leader.ackLoggingFrequency";
    private static int ackLoggingFrequency;

    static {
        ackLoggingFrequency = Integer.getInteger(ACK_LOGGING_FREQUENCY, 1000);
        LOG.info("{} = {}", ACK_LOGGING_FREQUENCY, ackLoggingFrequency);
    }

    public static void setAckLoggingFrequency(int frequency) {
        ackLoggingFrequency = frequency;
    }

    public static int getAckLoggingFrequency() {
        return ackLoggingFrequency;
    }

    final LeaderZooKeeperServer zk;

    final QuorumPeer self;

    // VisibleForTesting
    protected boolean quorumFormed = false;

    // the follower acceptor thread
    volatile LearnerCnxAcceptor cnxAcceptor = null;

    // list of all the learners, including followers and observers
    private final HashSet<LearnerHandler> learners = new HashSet<LearnerHandler>();

    private final BufferStats proposalStats;

    public BufferStats getProposalStats() {
        return proposalStats;
    }

    // beans for all learners
    private final ConcurrentHashMap<LearnerHandler, LearnerHandlerBean> connectionBeans = new ConcurrentHashMap<>();

    /**
     * Returns a copy of the current learner snapshot
     */
    public List<LearnerHandler> getLearners() {
        synchronized (learners) {
            return new ArrayList<LearnerHandler>(learners);
        }
    }

    // list of followers that are ready to follow (i.e synced with the leader)
    private final HashSet<LearnerHandler> forwardingFollowers = new HashSet<LearnerHandler>();

    /**
     * Returns a copy of the current forwarding follower snapshot
     */
    public List<LearnerHandler> getForwardingFollowers() {
        synchronized (forwardingFollowers) {
            return new ArrayList<LearnerHandler>(forwardingFollowers);
        }
    }

    public List<LearnerHandler> getNonVotingFollowers() {
        List<LearnerHandler> nonVotingFollowers = new ArrayList<LearnerHandler>();
        synchronized (forwardingFollowers) {
            for (LearnerHandler lh : forwardingFollowers) {
                if (!isParticipant(lh.getSid())) {
                    nonVotingFollowers.add(lh);
                }
            }
        }
        return nonVotingFollowers;
    }

    void addForwardingFollower(LearnerHandler lh) {
        synchronized (forwardingFollowers) {
            forwardingFollowers.add(lh);
            /*
            * Any changes on forwardiongFollowers could possible affect the need of Oracle.
            * */
            self.getQuorumVerifier().updateNeedOracle(new ArrayList<>(forwardingFollowers));
        }
    }

    private final HashSet<LearnerHandler> observingLearners = new HashSet<LearnerHandler>();

    /**
     * Returns a copy of the current observer snapshot
     */
    public List<LearnerHandler> getObservingLearners() {
        synchronized (observingLearners) {
            return new ArrayList<LearnerHandler>(observingLearners);
        }
    }

    private void addObserverLearnerHandler(LearnerHandler lh) {
        synchronized (observingLearners) {
            observingLearners.add(lh);
        }
    }

    public Iterable<Map<String, Object>> getObservingLearnersInfo() {
        Set<Map<String, Object>> info = new HashSet<>();
        synchronized (observingLearners) {
            for (LearnerHandler lh : observingLearners) {
                info.add(lh.getLearnerHandlerInfo());
            }
        }
        return info;
    }

    public void resetObserverConnectionStats() {
        synchronized (observingLearners) {
            for (LearnerHandler lh : observingLearners) {
                lh.resetObserverConnectionStats();
            }
        }
    }

    // Pending sync requests. Must access under 'this' lock.
    private final Map<Long, List<LearnerSyncRequest>> pendingSyncs = new HashMap<Long, List<LearnerSyncRequest>>();

    public synchronized int getNumPendingSyncs() {
        return pendingSyncs.size();
    }

    //Follower counter
    final AtomicLong followerCounter = new AtomicLong(-1);

    /**
     * Adds peer to the leader.
     *
     * @param learner
     *                instance of learner handle
     */
    @Override
    public void addLearnerHandler(LearnerHandler learner) {
        synchronized (learners) {
            learners.add(learner);
        }
    }

    /**
     * Remove the learner from the learner list
     *
     * @param peer
     */
    @Override
    public void removeLearnerHandler(LearnerHandler peer) {
        synchronized (forwardingFollowers) {
            forwardingFollowers.remove(peer);
        }
        synchronized (learners) {
            learners.remove(peer);
        }
        synchronized (observingLearners) {
            observingLearners.remove(peer);
        }
    }

    boolean isLearnerSynced(LearnerHandler peer) {
        synchronized (forwardingFollowers) {
            return forwardingFollowers.contains(peer);
        }
    }

    /**
     * Returns true if a quorum in qv is connected and synced with the leader
     * and false otherwise
     *
     * @param qv is a QuorumVerifier
     */
    public boolean isQuorumSynced(QuorumVerifier qv) {
        HashSet<Long> ids = new HashSet<Long>();
        if (qv.getVotingMembers().containsKey(self.getMyId())) {
            ids.add(self.getMyId());
        }
        synchronized (forwardingFollowers) {
            for (LearnerHandler learnerHandler : forwardingFollowers) {
                if (learnerHandler.synced() && qv.getVotingMembers().containsKey(learnerHandler.getSid())) {
                    ids.add(learnerHandler.getSid());
                }
            }
        }
        return qv.containsQuorum(ids);
    }

    private final List<ServerSocket> serverSockets = new LinkedList<>();

    public Leader(QuorumPeer self, LeaderZooKeeperServer zk) throws IOException {
        this.self = self;
        this.proposalStats = new BufferStats();

        Set<InetSocketAddress> addresses;
        if (self.getQuorumListenOnAllIPs()) {
            addresses = self.getQuorumAddress().getWildcardAddresses();
        } else {
            addresses = self.getQuorumAddress().getAllAddresses();
        }

        addresses.stream()
          .map(address -> createServerSocket(address, self.shouldUsePortUnification(), self.isSslQuorum()))
          .filter(Optional::isPresent)
          .map(Optional::get)
          .forEach(serverSockets::add);

        if (serverSockets.isEmpty()) {
            throw new IOException("Leader failed to initialize any of the following sockets: " + addresses);
        }

        this.zk = zk;
    }

    InetSocketAddress recreateInetSocketAddr(String hostString, int port) {
        return new InetSocketAddress(hostString, port);
    }

    Optional<ServerSocket> createServerSocket(InetSocketAddress address, boolean portUnification, boolean sslQuorum) {
        ServerSocket serverSocket;
        try {
            if (portUnification || sslQuorum) {
                serverSocket = new UnifiedServerSocket(self.getX509Util(), portUnification);
            } else {
                serverSocket = new ServerSocket();
            }
            serverSocket.setReuseAddress(true);
            serverSocket.bind(recreateInetSocketAddr(address.getHostString(), address.getPort()));
            return Optional.of(serverSocket);
        } catch (IOException e) {
            LOG.error("Couldn't bind to {}", address.toString(), e);
        }
        return Optional.empty();
    }

    /**
     * This message is for follower to expect diff
     */
    static final int DIFF = 13;

    /**
     * This is for follower to truncate its logs
     */
    static final int TRUNC = 14;

    /**
     * This is for follower to download the snapshots
     */
    static final int SNAP = 15;

    /**
     * This tells the leader that the connecting peer is actually an observer
     */
    static final int OBSERVERINFO = 16;

    /**
     * This message type is sent by the leader to indicate it's zxid and if
     * needed, its database.
     */
    static final int NEWLEADER = 10;

    /**
     * This message type is sent by a follower to pass the last zxid. This is here
     * for backward compatibility purposes.
     */
    static final int FOLLOWERINFO = 11;

    /**
     * This message type is sent by the leader to indicate that the follower is
     * now uptodate andt can start responding to clients.
     */
    static final int UPTODATE = 12;

    /**
     * This message is the first that a follower receives from the leader.
     * It has the protocol version and the epoch of the leader.
     */
    public static final int LEADERINFO = 17;

    /**
     * This message is used by the follow to ack a proposed epoch.
     */
    public static final int ACKEPOCH = 18;

    /**
     * This message type is sent to a leader to request and mutation operation.
     * The payload will consist of a request header followed by a request.
     */
    static final int REQUEST = 1;

    /**
     * This message type is sent by a leader to propose a mutation.
     */
    public static final int PROPOSAL = 2;

    /**
     * This message type is sent by a follower after it has synced a proposal.
     */
    static final int ACK = 3;

    /**
     * This message type is sent by a leader to commit a proposal and cause
     * followers to start serving the corresponding data.
     */
    static final int COMMIT = 4;

    /**
     * This message type is enchanged between follower and leader (initiated by
     * follower) to determine liveliness.
     */
    static final int PING = 5;

    /**
     * This message type is to validate a session that should be active.
     */
    static final int REVALIDATE = 6;

    /**
     * This message is a reply to a synchronize command flushing the pipe
     * between the leader and the follower.
     */
    static final int SYNC = 7;

    /**
     * This message type informs observers of a committed proposal.
     */
    static final int INFORM = 8;

    /**
     * Similar to COMMIT, only for a reconfig operation.
     */
    static final int COMMITANDACTIVATE = 9;

    /**
     * Similar to INFORM, only for a reconfig operation.
     */
    static final int INFORMANDACTIVATE = 19;

    final ConcurrentMap<Long, Proposal> outstandingProposals = new ConcurrentHashMap<Long, Proposal>();

    private final ConcurrentLinkedQueue<Proposal> toBeApplied = new ConcurrentLinkedQueue<Proposal>();

    // VisibleForTesting
    protected final Proposal newLeaderProposal = new Proposal();

    class LearnerCnxAcceptor extends ZooKeeperCriticalThread {

        private final AtomicBoolean stop = new AtomicBoolean(false);
        private final AtomicBoolean fail = new AtomicBoolean(false);

        LearnerCnxAcceptor() {
            super("LearnerCnxAcceptor-" + serverSockets.stream()
                      .map(ServerSocket::getLocalSocketAddress)
                      .map(Objects::toString)
                      .collect(Collectors.joining("|")),
                  zk.getZooKeeperServerListener());
        }

        @Override
        public void run() {
            if (!stop.get() && !serverSockets.isEmpty()) {
                ExecutorService executor = Executors.newFixedThreadPool(serverSockets.size());
                CountDownLatch latch = new CountDownLatch(serverSockets.size());

                serverSockets.forEach(serverSocket ->
                        executor.submit(new LearnerCnxAcceptorHandler(serverSocket, latch)));

                try {
                    latch.await();
                } catch (InterruptedException ie) {
                    LOG.error("Interrupted while sleeping in LearnerCnxAcceptor.", ie);
                } finally {
                    closeSockets();
                    executor.shutdown();
                    try {
                        if (!executor.awaitTermination(1, TimeUnit.SECONDS)) {
                            LOG.error("not all the LearnerCnxAcceptorHandler terminated properly");
                        }
                    } catch (InterruptedException ie) {
                        LOG.error("Interrupted while terminating LearnerCnxAcceptor.", ie);
                    }
                }
            }
        }

        public void halt() {
            stop.set(true);
            closeSockets();
        }

        class LearnerCnxAcceptorHandler implements Runnable {
            private ServerSocket serverSocket;
            private CountDownLatch latch;

            LearnerCnxAcceptorHandler(ServerSocket serverSocket, CountDownLatch latch) {
                this.serverSocket = serverSocket;
                this.latch = latch;
            }

            @Override
            public void run() {
                try {
                    Thread.currentThread().setName("LearnerCnxAcceptorHandler-" + serverSocket.getLocalSocketAddress());

                    while (!stop.get()) {
                        acceptConnections();
                    }
                } catch (Exception e) {
                    LOG.warn("Exception while accepting follower", e);
                    if (fail.compareAndSet(false, true)) {
                        handleException(getName(), e);
                        halt();
                    }
                } finally {
                    latch.countDown();
                }
            }

            private void acceptConnections() throws IOException {
                Socket socket = null;
                boolean error = false;
                try {
                    socket = serverSocket.accept();

                    // start with the initLimit, once the ack is processed
                    // in LearnerHandler switch to the syncLimit
                    socket.setSoTimeout(self.tickTime * self.initLimit);
                    socket.setTcpNoDelay(nodelay);

                    BufferedInputStream is = new BufferedInputStream(socket.getInputStream());
                    LearnerHandler fh = new LearnerHandler(socket, is, Leader.this);
                    fh.start();
                } catch (SocketException e) {
                    error = true;
                    if (stop.get()) {
                        LOG.warn("Exception while shutting down acceptor.", e);
                    } else {
                        throw e;
                    }
                } catch (SaslException e) {
                    LOG.error("Exception while connecting to quorum learner", e);
                    error = true;
                } catch (Exception e) {
                    error = true;
                    throw e;
                } finally {
                    // Don't leak sockets on errors
                    if (error && socket != null && !socket.isClosed()) {
                        try {
                            socket.close();
                        } catch (IOException e) {
                            LOG.warn("Error closing socket: " + socket, e);
                        }
                    }
                }
            }

        }

    }

    StateSummary leaderStateSummary;

    long epoch = -1;
    boolean waitingForNewEpoch = true;

    // when a reconfig occurs where the leader is removed or becomes an observer,
    // it does not commit ops after committing the reconfig
    boolean allowedToCommit = true;

    /**
     * Timestamp when this leader started serving request (Quorum is running)
     */
    private long leaderStartTime;

    public long getUptime() {
        if (leaderStartTime > 0) {
            return Time.currentElapsedTime() - leaderStartTime;
        }
        return 0;
    }

    /**
     * This method is main function that is called to lead
     *
     * @throws IOException
     * @throws InterruptedException
     */
    void lead() throws IOException, InterruptedException {
        self.end_fle = Time.currentElapsedTime();
        long electionTimeTaken = self.end_fle - self.start_fle;
        self.setElectionTimeTaken(electionTimeTaken);
        ServerMetrics.getMetrics().ELECTION_TIME.add(electionTimeTaken);
        LOG.info("LEADING - LEADER ELECTION TOOK - {} {}", electionTimeTaken, QuorumPeer.FLE_TIME_UNIT);
        self.start_fle = 0;
        self.end_fle = 0;

        zk.registerJMX(new LeaderBean(this, zk), self.jmxLocalPeerBean);

        try {
            self.setZabState(QuorumPeer.ZabState.DISCOVERY);
            self.tick.set(0);
            zk.loadData();

            leaderStateSummary = new StateSummary(self.getCurrentEpoch(), zk.getLastProcessedZxid());

            // Start thread that waits for connection requests from
            // new followers.
            cnxAcceptor = new LearnerCnxAcceptor();
            cnxAcceptor.start();

            long epoch = getEpochToPropose(self.getMyId(), self.getAcceptedEpoch());

            zk.setZxid(ZxidUtils.makeZxid(epoch, 0));

            synchronized (this) {
                lastProposed = zk.getZxid();
            }

            newLeaderProposal.packet = new QuorumPacket(NEWLEADER, zk.getZxid(), null, null);

            if ((newLeaderProposal.packet.getZxid() & 0xffffffffL) != 0) {
                LOG.info("NEWLEADER proposal has Zxid of {}", Long.toHexString(newLeaderProposal.packet.getZxid()));
            }

            QuorumVerifier lastSeenQV = self.getLastSeenQuorumVerifier();
            QuorumVerifier curQV = self.getQuorumVerifier();
            if (curQV.getVersion() == 0 && curQV.getVersion() == lastSeenQV.getVersion()) {
                // This was added in ZOOKEEPER-1783. The initial config has version 0 (not explicitly
                // specified by the user; the lack of version in a config file is interpreted as version=0).
                // As soon as a config is established we would like to increase its version so that it
                // takes presedence over other initial configs that were not established (such as a config
                // of a server trying to join the ensemble, which may be a partial view of the system, not the full config).
                // We chose to set the new version to the one of the NEWLEADER message. However, before we can do that
                // there must be agreement on the new version, so we can only change the version when sending/receiving UPTODATE,
                // not when sending/receiving NEWLEADER. In other words, we can't change curQV here since its the committed quorum verifier,
                // and there's still no agreement on the new version that we'd like to use. Instead, we use
                // lastSeenQuorumVerifier which is being sent with NEWLEADER message
                // so its a good way to let followers know about the new version. (The original reason for sending
                // lastSeenQuorumVerifier with NEWLEADER is so that the leader completes any potentially uncommitted reconfigs
                // that it finds before starting to propose operations. Here we're reusing the same code path for
                // reaching consensus on the new version number.)

                // It is important that this is done before the leader executes waitForEpochAck,
                // so before LearnerHandlers return from their waitForEpochAck
                // hence before they construct the NEWLEADER message containing
                // the last-seen-quorumverifier of the leader, which we change below
                try {
                    LOG.debug(String.format("set lastSeenQuorumVerifier to currentQuorumVerifier (%s)", curQV.toString()));
                    QuorumVerifier newQV = self.configFromString(curQV.toString());
                    newQV.setVersion(zk.getZxid());
                    self.setLastSeenQuorumVerifier(newQV, true);
                } catch (Exception e) {
                    throw new IOException(e);
                }
            }

            newLeaderProposal.addQuorumVerifier(self.getQuorumVerifier());
            if (self.getLastSeenQuorumVerifier().getVersion() > self.getQuorumVerifier().getVersion()) {
                newLeaderProposal.addQuorumVerifier(self.getLastSeenQuorumVerifier());
            }

            // We have to get at least a majority of servers in sync with
            // us. We do this by waiting for the NEWLEADER packet to get
            // acknowledged

            waitForEpochAck(self.getMyId(), leaderStateSummary);
            self.setCurrentEpoch(epoch);
            self.setLeaderAddressAndId(self.getQuorumAddress(), self.getMyId());
            self.setZabState(QuorumPeer.ZabState.SYNCHRONIZATION);

            try {
                waitForNewLeaderAck(self.getMyId(), zk.getZxid());
            } catch (InterruptedException e) {
                shutdown("Waiting for a quorum of followers, only synced with sids: [ "
                         + newLeaderProposal.ackSetsToString()
                         + " ]");
                HashSet<Long> followerSet = new HashSet<Long>();

                for (LearnerHandler f : getLearners()) {
                    if (self.getQuorumVerifier().getVotingMembers().containsKey(f.getSid())) {
                        followerSet.add(f.getSid());
                    }
                }
                boolean initTicksShouldBeIncreased = true;
                for (Proposal.QuorumVerifierAcksetPair qvAckset : newLeaderProposal.qvAcksetPairs) {
                    if (!qvAckset.getQuorumVerifier().containsQuorum(followerSet)) {
                        initTicksShouldBeIncreased = false;
                        break;
                    }
                }
                if (initTicksShouldBeIncreased) {
                    LOG.warn("Enough followers present. Perhaps the initTicks need to be increased.");
                }
                return;
            }

            startZkServer();

            /**
             * WARNING: do not use this for anything other than QA testing
             * on a real cluster. Specifically to enable verification that quorum
             * can handle the lower 32bit roll-over issue identified in
             * ZOOKEEPER-1277. Without this option it would take a very long
             * time (on order of a month say) to see the 4 billion writes
             * necessary to cause the roll-over to occur.
             *
             * This field allows you to override the zxid of the server. Typically
             * you'll want to set it to something like 0xfffffff0 and then
             * start the quorum, run some operations and see the re-election.
             */
            String initialZxid = System.getProperty("zookeeper.testingonly.initialZxid");
            if (initialZxid != null) {
                long zxid = Long.parseLong(initialZxid);
                zk.setZxid((zk.getZxid() & 0xffffffff00000000L) | zxid);
            }

            if (!System.getProperty("zookeeper.leaderServes", "yes").equals("no")) {
                self.setZooKeeperServer(zk);
            }

            self.setZabState(QuorumPeer.ZabState.BROADCAST);
            self.adminServer.setZooKeeperServer(zk);

            // We ping twice a tick, so we only update the tick every other
            // iteration
            boolean tickSkip = true;
            // If not null then shutdown this leader
            String shutdownMessage = null;

            while (true) {
                synchronized (this) {
                    long start = Time.currentElapsedTime();
                    long cur = start;
                    long end = start + self.tickTime / 2;
                    while (cur < end) {
                        wait(end - cur);
                        cur = Time.currentElapsedTime();
                    }

                    if (!tickSkip) {
                        self.tick.incrementAndGet();
                    }

                    // We use an instance of SyncedLearnerTracker to
                    // track synced learners to make sure we still have a
                    // quorum of current (and potentially next pending) view.
                    SyncedLearnerTracker syncedAckSet = new SyncedLearnerTracker();
                    syncedAckSet.addQuorumVerifier(self.getQuorumVerifier());
                    if (self.getLastSeenQuorumVerifier() != null
                        && self.getLastSeenQuorumVerifier().getVersion() > self.getQuorumVerifier().getVersion()) {
                        syncedAckSet.addQuorumVerifier(self.getLastSeenQuorumVerifier());
                    }

                    syncedAckSet.addAck(self.getMyId());

                    for (LearnerHandler f : getLearners()) {
                        if (f.synced()) {
                            syncedAckSet.addAck(f.getSid());
                        }
                    }

                    // check leader running status
                    if (!this.isRunning()) {
                        // set shutdown flag
                        shutdownMessage = "Unexpected internal error";
                        break;
                    }

                    /*
                     *
                     * We will need to re-validate the outstandingProposal to maintain the progress of ZooKeeper.
                     * It is likely a proposal is waiting for enough ACKs to be committed. The proposals are sent out, but the
                     * only follower goes away which makes the proposals will not be committed until the follower recovers back.
                     * An earlier proposal which is not committed will block any further proposals. So, We need to re-validate those
                     * outstanding proposal with the help from Oracle. A key point in the process of re-validation is that the proposals
                     * need to be processed in order.
                     *
                     * We make the whole method blocking to avoid any possible race condition on outstandingProposal and lastCommitted
                     * as well as to avoid nested synchronization.
                     *
                     * As a more generic approach, we pass the object of forwardingFollowers to QuorumOracleMaj to determine if we need
                     * the help from Oracle.
                     *
                     *
                     * the size of outstandingProposals can be 1. The only one outstanding proposal is the one waiting for the ACK from
                     * the leader itself.
                     * */
                    if (!tickSkip && !syncedAckSet.hasAllQuorums()
                        && !(self.getQuorumVerifier().overrideQuorumDecision(getForwardingFollowers()) && self.getQuorumVerifier().revalidateOutstandingProp(this, new ArrayList<>(outstandingProposals.values()), lastCommitted))) {
                        // Lost quorum of last committed and/or last proposed
                        // config, set shutdown flag
                        shutdownMessage = "Not sufficient followers synced, only synced with sids: [ "
                                          + syncedAckSet.ackSetsToString()
                                          + " ]";
                        break;
                    }
                    tickSkip = !tickSkip;
                }
                for (LearnerHandler f : getLearners()) {
                    f.ping();
                }
            }
            if (shutdownMessage != null) {
                shutdown(shutdownMessage);
                // leader goes in looking state
            }
        } finally {
            zk.unregisterJMX(this);
        }
    }

    boolean isShutdown;

    /**
     * Close down all the LearnerHandlers
     */
    void shutdown(String reason) {
        LOG.info("Shutting down");

        if (isShutdown) {
            return;
        }

        LOG.info("Shutdown called. For the reason {}", reason);

        if (cnxAcceptor != null) {
            cnxAcceptor.halt();
        } else {
            closeSockets();
        }

        // NIO should not accept conenctions
        self.setZooKeeperServer(null);
        self.adminServer.setZooKeeperServer(null);
        self.closeAllConnections();
        // shutdown the previous zk
        if (zk != null) {
            zk.shutdown();
        }
        synchronized (learners) {
            for (Iterator<LearnerHandler> it = learners.iterator(); it.hasNext(); ) {
                LearnerHandler f = it.next();
                it.remove();
                f.shutdown();
            }
        }
        isShutdown = true;
    }

    synchronized void closeSockets() {
       for (ServerSocket serverSocket : serverSockets) {
           if (!serverSocket.isClosed()) {
               try {
                   serverSocket.close();
               } catch (IOException e) {
                   LOG.warn("Ignoring unexpected exception during close {}", serverSocket, e);
               }
           }
       }
    }

    /** In a reconfig operation, this method attempts to find the best leader for next configuration.
     *  If the current leader is a voter in the next configuartion, then it remains the leader.
     *  Otherwise, choose one of the new voters that acked the reconfiguartion, such that it is as
     * up-to-date as possible, i.e., acked as many outstanding proposals as possible.
     *
     * @param reconfigProposal
     * @param zxid of the reconfigProposal
     * @return server if of the designated leader
     */

    private long getDesignatedLeader(Proposal reconfigProposal, long zxid) {
        //new configuration
        Proposal.QuorumVerifierAcksetPair newQVAcksetPair = reconfigProposal.qvAcksetPairs.get(reconfigProposal.qvAcksetPairs.size() - 1);

        //check if I'm in the new configuration with the same quorum address -
        // if so, I'll remain the leader
        if (newQVAcksetPair.getQuorumVerifier().getVotingMembers().containsKey(self.getMyId())
            && newQVAcksetPair.getQuorumVerifier().getVotingMembers().get(self.getMyId()).addr.equals(self.getQuorumAddress())) {
            return self.getMyId();
        }
        // start with an initial set of candidates that are voters from new config that
        // acknowledged the reconfig op (there must be a quorum). Choose one of them as
        // current leader candidate
        HashSet<Long> candidates = new HashSet<Long>(newQVAcksetPair.getAckset());
        candidates.remove(self.getMyId()); // if we're here, I shouldn't be the leader
        long curCandidate = candidates.iterator().next();

        //go over outstanding ops in order, and try to find a candidate that acked the most ops.
        //this way it will be the most up-to-date and we'll minimize the number of ops that get dropped

        long curZxid = zxid + 1;
        Proposal p = outstandingProposals.get(curZxid);

        while (p != null && !candidates.isEmpty()) {
            for (Proposal.QuorumVerifierAcksetPair qvAckset : p.qvAcksetPairs) {
                //reduce the set of candidates to those that acknowledged p
                candidates.retainAll(qvAckset.getAckset());
                //no candidate acked p, return the best candidate found so far
                if (candidates.isEmpty()) {
                    return curCandidate;
                }
                //update the current candidate, and if it is the only one remaining, return it
                curCandidate = candidates.iterator().next();
                if (candidates.size() == 1) {
                    return curCandidate;
                }
            }
            curZxid++;
            p = outstandingProposals.get(curZxid);
        }

        return curCandidate;
    }

    /**
     * @return True if committed, otherwise false.
     **/
    public synchronized boolean tryToCommit(Proposal p, long zxid, SocketAddress followerAddr) {
        // make sure that ops are committed in order. With reconfigurations it is now possible
        // that different operations wait for different sets of acks, and we still want to enforce
        // that they are committed in order. Currently we only permit one outstanding reconfiguration
        // such that the reconfiguration and subsequent outstanding ops proposed while the reconfig is
        // pending all wait for a quorum of old and new config, so it's not possible to get enough acks
        // for an operation without getting enough acks for preceding ops. But in the future if multiple
        // concurrent reconfigs are allowed, this can happen.
        if (outstandingProposals.containsKey(zxid - 1)) {
            return false;
        }

        // in order to be committed, a proposal must be accepted by a quorum.
        //
        // getting a quorum from all necessary configurations.
        if (!p.hasAllQuorums()) {
            return false;
        }

        // commit proposals in order
        if (zxid != lastCommitted + 1) {
            LOG.warn(
                "Commiting zxid 0x{} from {} not first!",
                Long.toHexString(zxid),
                followerAddr);
            LOG.warn("First is 0x{}", Long.toHexString(lastCommitted + 1));
        }

        outstandingProposals.remove(zxid);

        if (p.request != null) {
            toBeApplied.add(p);
        }

        if (p.request == null) {
            LOG.warn("Going to commit null: {}", p);
        } else if (p.request.getHdr().getType() == OpCode.reconfig) {
            LOG.debug("Committing a reconfiguration! {}", outstandingProposals.size());

            //if this server is voter in new config with the same quorum address,
            //then it will remain the leader
            //otherwise an up-to-date follower will be designated as leader. This saves
            //leader election time, unless the designated leader fails
            Long designatedLeader = getDesignatedLeader(p, zxid);

            QuorumVerifier newQV = p.qvAcksetPairs.get(p.qvAcksetPairs.size() - 1).getQuorumVerifier();

            self.processReconfig(newQV, designatedLeader, zk.getZxid(), true);

            if (designatedLeader != self.getMyId()) {
                LOG.info(String.format("Committing a reconfiguration (reconfigEnabled=%s); this leader is not the designated "
                        + "leader anymore, setting allowedToCommit=false", self.isReconfigEnabled()));
                allowedToCommit = false;
            }

            // we're sending the designated leader, and if the leader is changing the followers are
            // responsible for closing the connection - this way we are sure that at least a majority of them
            // receive the commit message.
            commitAndActivate(zxid, designatedLeader);
            informAndActivate(p, designatedLeader);
        } else {
            p.request.logLatency(ServerMetrics.getMetrics().QUORUM_ACK_LATENCY);
            commit(zxid);
            inform(p);
        }
        zk.commitProcessor.commit(p.request);
        if (pendingSyncs.containsKey(zxid)) {
            for (LearnerSyncRequest r : pendingSyncs.remove(zxid)) {
                sendSync(r);
            }
        }

        return true;
    }

    /**
     * Keep a count of acks that are received by the leader for a particular
     * proposal
     *
     * @param sid is the id of the server that sent the ack
     * @param zxid is the zxid of the proposal sent out
     * @param followerAddr
     */
    @Override
    public synchronized void processAck(long sid, long zxid, SocketAddress followerAddr) {
        if (!allowedToCommit) {
            return; // last op committed was a leader change - from now on
        }
        // the new leader should commit
        if (LOG.isTraceEnabled()) {
            LOG.trace("Ack zxid: 0x{}", Long.toHexString(zxid));
            for (Proposal p : outstandingProposals.values()) {
                long packetZxid = p.packet.getZxid();
                LOG.trace("outstanding proposal: 0x{}", Long.toHexString(packetZxid));
            }
            LOG.trace("outstanding proposals all");
        }

        if ((zxid & 0xffffffffL) == 0) {
            /*
             * We no longer process NEWLEADER ack with this method. However,
             * the learner sends an ack back to the leader after it gets
             * UPTODATE, so we just ignore the message.
             */
            return;
        }

        if (outstandingProposals.size() == 0) {
            LOG.debug("outstanding is 0");
            return;
        }
        if (lastCommitted >= zxid) {
            LOG.debug(
                "proposal has already been committed, pzxid: 0x{} zxid: 0x{}",
                Long.toHexString(lastCommitted),
                Long.toHexString(zxid));
            // The proposal has already been committed
            return;
        }
        Proposal p = outstandingProposals.get(zxid);
        if (p == null) {
            LOG.warn("Trying to commit future proposal: zxid 0x{} from {}", Long.toHexString(zxid), followerAddr);
            return;
        }

        if (ackLoggingFrequency > 0 && (zxid % ackLoggingFrequency == 0)) {
            p.request.logLatency(ServerMetrics.getMetrics().ACK_LATENCY, Long.toString(sid));
        }

        p.addAck(sid);

        boolean hasCommitted = tryToCommit(p, zxid, followerAddr);

        // If p is a reconfiguration, multiple other operations may be ready to be committed,
        // since operations wait for different sets of acks.
        // Currently we only permit one outstanding reconfiguration at a time
        // such that the reconfiguration and subsequent outstanding ops proposed while the reconfig is
        // pending all wait for a quorum of old and new config, so its not possible to get enough acks
        // for an operation without getting enough acks for preceding ops. But in the future if multiple
        // concurrent reconfigs are allowed, this can happen and then we need to check whether some pending
        // ops may already have enough acks and can be committed, which is what this code does.

        if (hasCommitted && p.request != null && p.request.getHdr().getType() == OpCode.reconfig) {
            long curZxid = zxid;
            while (allowedToCommit && hasCommitted && p != null) {
                curZxid++;
                p = outstandingProposals.get(curZxid);
                if (p != null) {
                    hasCommitted = tryToCommit(p, curZxid, null);
                }
            }
        }
    }

    static class ToBeAppliedRequestProcessor implements RequestProcessor {

        private final RequestProcessor next;

        private final Leader leader;

        /**
         * This request processor simply maintains the toBeApplied list. For
         * this to work next must be a FinalRequestProcessor and
         * FinalRequestProcessor.processRequest MUST process the request
         * synchronously!
         *
         * @param next
         *                a reference to the FinalRequestProcessor
         */
        ToBeAppliedRequestProcessor(RequestProcessor next, Leader leader) {
            if (!(next instanceof FinalRequestProcessor)) {
                throw new RuntimeException(ToBeAppliedRequestProcessor.class.getName()
                                           + " must be connected to "
                                           + FinalRequestProcessor.class.getName()
                                           + " not "
                                           + next.getClass().getName());
            }
            this.leader = leader;
            this.next = next;
        }

        /*
         * (non-Javadoc)
         *
         * @see org.apache.zookeeper.server.RequestProcessor#processRequest(org.apache.zookeeper.server.Request)
         */
        public void processRequest(Request request) throws RequestProcessorException {
            next.processRequest(request);

            // The only requests that should be on toBeApplied are write
            // requests, for which we will have a hdr. We can't simply use
            // request.zxid here because that is set on read requests to equal
            // the zxid of the last write op.
            if (request.getHdr() != null) {
                long zxid = request.getHdr().getZxid();
                Iterator<Proposal> iter = leader.toBeApplied.iterator();
                if (iter.hasNext()) {
                    Proposal p = iter.next();
                    if (p.request != null && p.request.zxid == zxid) {
                        iter.remove();
                        return;
                    }
                }
                LOG.error("Committed request not found on toBeApplied: {}", request);
            }
        }

        /*
         * (non-Javadoc)
         *
         * @see org.apache.zookeeper.server.RequestProcessor#shutdown()
         */
        public void shutdown() {
            LOG.info("Shutting down");
            next.shutdown();
        }

    }

    /**
     * send a packet to all the followers ready to follow
     *
     * @param qp
     *                the packet to be sent
     */
    void sendPacket(QuorumPacket qp) {
        synchronized (forwardingFollowers) {
            for (LearnerHandler f : forwardingFollowers) {
                f.queuePacket(qp);
            }
        }
    }

    /**
     * send a packet to all observers
     */
    void sendObserverPacket(QuorumPacket qp) {
        for (LearnerHandler f : getObservingLearners()) {
            f.queuePacket(qp);
        }
    }

    long lastCommitted = -1;

    /**
     * Create a commit packet and send it to all the members of the quorum
     *
     * @param zxid
     */
    public void commit(long zxid) {
        synchronized (this) {
            lastCommitted = zxid;
        }
        QuorumPacket qp = new QuorumPacket(Leader.COMMIT, zxid, null, null);
        sendPacket(qp);
        ServerMetrics.getMetrics().COMMIT_COUNT.add(1);
    }

    //commit and send some info
    public void commitAndActivate(long zxid, long designatedLeader) {
        synchronized (this) {
            lastCommitted = zxid;
        }

        byte[] data = new byte[8];
        ByteBuffer buffer = ByteBuffer.wrap(data);
        buffer.putLong(designatedLeader);

        QuorumPacket qp = new QuorumPacket(Leader.COMMITANDACTIVATE, zxid, data, null);
        sendPacket(qp);
    }

    /**
     * Create an inform packet and send it to all observers.
     */
    public void inform(Proposal proposal) {
        QuorumPacket qp = new QuorumPacket(Leader.INFORM, proposal.request.zxid, proposal.packet.getData(), null);
        sendObserverPacket(qp);
    }

    public static QuorumPacket buildInformAndActivePacket(long zxid, long designatedLeader, byte[] proposalData) {
        byte[] data = new byte[proposalData.length + 8];
        ByteBuffer buffer = ByteBuffer.wrap(data);
        buffer.putLong(designatedLeader);
        buffer.put(proposalData);

        return new QuorumPacket(Leader.INFORMANDACTIVATE, zxid, data, null);
    }

    /**
     * Create an inform and activate packet and send it to all observers.
     */
    public void informAndActivate(Proposal proposal, long designatedLeader) {
        sendObserverPacket(buildInformAndActivePacket(proposal.request.zxid, designatedLeader, proposal.packet.getData()));
    }

    long lastProposed;

    @Override
    public synchronized long getLastProposed() {
        return lastProposed;
    }

    /**
     * Returns the current epoch of the leader.
     */
    public long getEpoch() {
        return ZxidUtils.getEpochFromZxid(lastProposed);
    }

    @SuppressWarnings("serial")
    public static class XidRolloverException extends Exception {

        public XidRolloverException(String message) {
            super(message);
        }

    }

    /**
     * create a proposal and send it out to all the members
     *
     * @param request
     * @return the proposal that is queued to send to all the members
     */
    public Proposal propose(Request request) throws XidRolloverException {
        if (request.isThrottled()) {
            LOG.error("Throttled request send as proposal: {}. Exiting.", request);
            ServiceUtils.requestSystemExit(ExitCode.UNEXPECTED_ERROR.getValue());
        }
        /**
         * Address the rollover issue. All lower 32bits set indicate a new leader
         * election. Force a re-election instead. See ZOOKEEPER-1277
         */
        if ((request.zxid & 0xffffffffL) == 0xffffffffL) {
            String msg = "zxid lower 32 bits have rolled over, forcing re-election, and therefore new epoch start";
            shutdown(msg);
            throw new XidRolloverException(msg);
        }

        byte[] data = request.getSerializeData();
        proposalStats.setLastBufferSize(data.length);
        QuorumPacket pp = new QuorumPacket(Leader.PROPOSAL, request.zxid, data, null);

        Proposal p = new Proposal();
        p.packet = pp;
        p.request = request;

        synchronized (this) {
            p.addQuorumVerifier(self.getQuorumVerifier());

            if (request.getHdr().getType() == OpCode.reconfig) {
                self.setLastSeenQuorumVerifier(request.qv, true);
            }

            if (self.getQuorumVerifier().getVersion() < self.getLastSeenQuorumVerifier().getVersion()) {
                p.addQuorumVerifier(self.getLastSeenQuorumVerifier());
            }

            LOG.debug("Proposing:: {}", request);

            lastProposed = p.packet.getZxid();
            outstandingProposals.put(lastProposed, p);
            sendPacket(pp);
        }
        ServerMetrics.getMetrics().PROPOSAL_COUNT.add(1);
        return p;
    }

    /**
     * Process sync requests
     *
     * @param r the request
     */

    public synchronized void processSync(LearnerSyncRequest r) {
        if (outstandingProposals.isEmpty()) {
            sendSync(r);
        } else {
            pendingSyncs.computeIfAbsent(lastProposed, k -> new ArrayList<>()).add(r);
        }
    }

    /**
     * Sends a sync message to the appropriate server
     */
    public void sendSync(LearnerSyncRequest r) {
        QuorumPacket qp = new QuorumPacket(Leader.SYNC, 0, null, null);
        r.fh.queuePacket(qp);
    }

    /**
     * lets the leader know that a follower is capable of following and is done
     * syncing
     *
     * @param handler handler of the follower
     * @return last proposed zxid
     */
    @Override
    public synchronized long startForwarding(LearnerHandler handler, long lastSeenZxid) {
        // Queue up any outstanding requests enabling the receipt of
        // new requests
        if (lastProposed > lastSeenZxid) {
            for (Proposal p : toBeApplied) {
                if (p.packet.getZxid() <= lastSeenZxid) {
                    continue;
                }
                handler.queuePacket(p.packet);
                // Since the proposal has been committed we need to send the
                // commit message also
                QuorumPacket qp = new QuorumPacket(Leader.COMMIT, p.packet.getZxid(), null, null);
                handler.queuePacket(qp);
            }
            // Only participant need to get outstanding proposals
            if (handler.getLearnerType() == LearnerType.PARTICIPANT) {
                List<Long> zxids = new ArrayList<Long>(outstandingProposals.keySet());
                Collections.sort(zxids);
                for (Long zxid : zxids) {
                    if (zxid <= lastSeenZxid) {
                        continue;
                    }
                    handler.queuePacket(outstandingProposals.get(zxid).packet);
                }
            }
        }
        if (handler.getLearnerType() == LearnerType.PARTICIPANT) {
            addForwardingFollower(handler);
        } else {
            addObserverLearnerHandler(handler);
        }

        return lastProposed;
    }

    @Override
    public void waitForStartup() throws InterruptedException {
        synchronized (zk) {
            while (!zk.isRunning() && !Thread.currentThread().isInterrupted()) {
                zk.wait(20);
            }
        }
    }

    // VisibleForTesting
    protected final Set<Long> connectingFollowers = new HashSet<Long>();

    private volatile boolean quitWaitForEpoch = false;
    private volatile long timeStartWaitForEpoch = -1;
    private volatile SyncedLearnerTracker voteSet;

    public static final String MAX_TIME_TO_WAIT_FOR_EPOCH = "zookeeper.leader.maxTimeToWaitForEpoch";
    private static int maxTimeToWaitForEpoch;

    static {
        maxTimeToWaitForEpoch = Integer.getInteger(MAX_TIME_TO_WAIT_FOR_EPOCH, -1);
        LOG.info("{} = {}ms", MAX_TIME_TO_WAIT_FOR_EPOCH, maxTimeToWaitForEpoch);
    }

    // visible for test
    public static void setMaxTimeToWaitForEpoch(int maxTimeToWaitForEpoch) {
        Leader.maxTimeToWaitForEpoch = maxTimeToWaitForEpoch;
        LOG.info("Set {} to {}ms", MAX_TIME_TO_WAIT_FOR_EPOCH, Leader.maxTimeToWaitForEpoch);
    }

    /**
     * Quit condition:
     *
     * 1 voter goes to looking again and time waitForEpoch &gt; maxTimeToWaitForEpoch
     *
     * Note: the voter may go to looking again in case of:
     * 1. change mind in the last minute when received a different notification
     * 2. the leader hadn't started leading when it tried to connect to it
     * 3. connection broken between the voter and leader
     * 4. voter being shutdown or restarted
     */
    private void quitLeading() {
        synchronized (connectingFollowers) {
            quitWaitForEpoch = true;
            connectingFollowers.notifyAll();
        }
        ServerMetrics.getMetrics().QUIT_LEADING_DUE_TO_DISLOYAL_VOTER.add(1);
        LOG.info("Quit leading due to voter changed mind.");
    }

    public void setLeadingVoteSet(SyncedLearnerTracker voteSet) {
        this.voteSet = voteSet;
    }

    public void reportLookingSid(long sid) {
        if (maxTimeToWaitForEpoch < 0 || timeStartWaitForEpoch < 0 || !waitingForNewEpoch) {
            return;
        }
        if (voteSet == null || !voteSet.hasSid(sid)) {
            return;
        }
        if (Time.currentElapsedTime() - timeStartWaitForEpoch > maxTimeToWaitForEpoch) {
            quitLeading();
        }
    }

    @Override
    public long getEpochToPropose(long sid, long lastAcceptedEpoch) throws InterruptedException, IOException {
        synchronized (connectingFollowers) {
            if (!waitingForNewEpoch) {
                return epoch;
            }
            if (lastAcceptedEpoch >= epoch) {
                epoch = lastAcceptedEpoch + 1;
            }
            if (isParticipant(sid)) {
                connectingFollowers.add(sid);
            }
            QuorumVerifier verifier = self.getQuorumVerifier();
            if (connectingFollowers.contains(self.getMyId()) && verifier.containsQuorum(connectingFollowers)) {
                waitingForNewEpoch = false;
                self.setAcceptedEpoch(epoch);
                connectingFollowers.notifyAll();
            } else {
                long start = Time.currentElapsedTime();
                if (sid == self.getMyId()) {
                    timeStartWaitForEpoch = start;
                }
                long cur = start;
                long end = start + self.getInitLimit() * self.getTickTime();
                while (waitingForNewEpoch && cur < end && !quitWaitForEpoch) {
                    connectingFollowers.wait(end - cur);
                    cur = Time.currentElapsedTime();
                }
                if (waitingForNewEpoch) {
                    throw new InterruptedException("Timeout while waiting for epoch from quorum");
                }
            }
            return epoch;
        }
    }

    @Override
    public ZKDatabase getZKDatabase() {
        return zk.getZKDatabase();
    }

    // VisibleForTesting
    protected final Set<Long> electingFollowers = new HashSet<Long>();
    // VisibleForTesting
    protected boolean electionFinished = false;

    @Override
    public void waitForEpochAck(long id, StateSummary ss) throws IOException, InterruptedException {
        synchronized (electingFollowers) {
            if (electionFinished) {
                return;
            }
            if (ss.getCurrentEpoch() != -1) {
                if (ss.isMoreRecentThan(leaderStateSummary)) {
                    throw new IOException("Follower is ahead of the leader, leader summary: "
                                          + leaderStateSummary.getCurrentEpoch()
                                          + " (current epoch), "
                                          + leaderStateSummary.getLastZxid()
                                          + " (last zxid)");
                }
                if (ss.getLastZxid() != -1 && isParticipant(id)) {
                    electingFollowers.add(id);
                }
            }
            QuorumVerifier verifier = self.getQuorumVerifier();
            if (electingFollowers.contains(self.getMyId()) && verifier.containsQuorum(electingFollowers)) {
                electionFinished = true;
                electingFollowers.notifyAll();
            } else {
                long start = Time.currentElapsedTime();
                long cur = start;
                long end = start + self.getInitLimit() * self.getTickTime();
                while (!electionFinished && cur < end) {
                    electingFollowers.wait(end - cur);
                    cur = Time.currentElapsedTime();
                }
                if (!electionFinished) {
                    throw new InterruptedException("Timeout while waiting for epoch to be acked by quorum");
                }
            }
        }
    }

    /**
     * Return a list of sid in set as string
     */
    private String getSidSetString(Set<Long> sidSet) {
        StringBuilder sids = new StringBuilder();
        Iterator<Long> iter = sidSet.iterator();
        while (iter.hasNext()) {
            sids.append(iter.next());
            if (!iter.hasNext()) {
                break;
            }
            sids.append(",");
        }
        return sids.toString();
    }

    /**
     * Start up Leader ZooKeeper server and initialize zxid to the new epoch
     */
    private synchronized void startZkServer() {
        // Update lastCommitted and Db's zxid to a value representing the new epoch
        lastCommitted = zk.getZxid();
        LOG.info("Have quorum of supporters, sids: [{}]; starting up and setting last processed zxid: 0x{}",
                 newLeaderProposal.ackSetsToString(),
                 Long.toHexString(zk.getZxid()));

        if (self.isReconfigEnabled()) {
            /*
             * ZOOKEEPER-1324. the leader sends the new config it must complete
             *  to others inside a NEWLEADER message (see LearnerHandler where
             *  the NEWLEADER message is constructed), and once it has enough
             *  acks we must execute the following code so that it applies the
             *  config to itself.
             */
            QuorumVerifier newQV = self.getLastSeenQuorumVerifier();

            Long designatedLeader = getDesignatedLeader(newLeaderProposal, zk.getZxid());

            self.processReconfig(newQV, designatedLeader, zk.getZxid(), true);
            if (designatedLeader != self.getMyId()) {
                LOG.warn("This leader is not the designated leader, it will be initialized with allowedToCommit = false");
                allowedToCommit = false;
            }
        } else {
            LOG.info("Dynamic reconfig feature is disabled, skip designatedLeader calculation and reconfig processing.");
        }

        leaderStartTime = Time.currentElapsedTime();
        zk.startup();
        /*
         * Update the election vote here to ensure that all members of the
         * ensemble report the same vote to new servers that start up and
         * send leader election notifications to the ensemble.
         *
         * @see https://issues.apache.org/jira/browse/ZOOKEEPER-1732
         */
        self.updateElectionVote(getEpoch());

        zk.getZKDatabase().setlastProcessedZxid(zk.getZxid());
    }

    /**
     * Process NEWLEADER ack of a given sid and wait until the leader receives
     * sufficient acks.
     *
     * @param sid
     * @throws InterruptedException
     */
    @Override
    public void waitForNewLeaderAck(long sid, long zxid) throws InterruptedException {

        synchronized (newLeaderProposal.qvAcksetPairs) {

            if (quorumFormed) {
                return;
            }

            long currentZxid = newLeaderProposal.packet.getZxid();
            if (zxid != currentZxid) {
                LOG.error(
                    "NEWLEADER ACK from sid: {} is from a different epoch - current 0x{} received 0x{}",
                    sid,
                    Long.toHexString(currentZxid),
                    Long.toHexString(zxid));
                return;
            }

            /*
             * Note that addAck already checks that the learner
             * is a PARTICIPANT.
             */
            newLeaderProposal.addAck(sid);

            if (newLeaderProposal.hasAllQuorums()) {
                quorumFormed = true;
                newLeaderProposal.qvAcksetPairs.notifyAll();
            } else {
                long start = Time.currentElapsedTime();
                long cur = start;
                long end = start + self.getInitLimit() * self.getTickTime();
                while (!quorumFormed && cur < end) {
                    newLeaderProposal.qvAcksetPairs.wait(end - cur);
                    cur = Time.currentElapsedTime();
                }
                if (!quorumFormed) {
                    throw new InterruptedException("Timeout while waiting for NEWLEADER to be acked by quorum");
                }
            }
        }
    }

    /**
     * Get string representation of a given packet type
     * @param packetType
     * @return string representing the packet type
     */
    public static String getPacketType(int packetType) {
        switch (packetType) {
        case DIFF:
            return "DIFF";
        case TRUNC:
            return "TRUNC";
        case SNAP:
            return "SNAP";
        case OBSERVERINFO:
            return "OBSERVERINFO";
        case NEWLEADER:
            return "NEWLEADER";
        case FOLLOWERINFO:
            return "FOLLOWERINFO";
        case UPTODATE:
            return "UPTODATE";
        case LEADERINFO:
            return "LEADERINFO";
        case ACKEPOCH:
            return "ACKEPOCH";
        case REQUEST:
            return "REQUEST";
        case PROPOSAL:
            return "PROPOSAL";
        case ACK:
            return "ACK";
        case COMMIT:
            return "COMMIT";
        case COMMITANDACTIVATE:
            return "COMMITANDACTIVATE";
        case PING:
            return "PING";
        case REVALIDATE:
            return "REVALIDATE";
        case SYNC:
            return "SYNC";
        case INFORM:
            return "INFORM";
        case INFORMANDACTIVATE:
            return "INFORMANDACTIVATE";
        default:
            return "UNKNOWN";
        }
    }

    private boolean isRunning() {
        return self.isRunning() && zk.isRunning();
    }

    private boolean isParticipant(long sid) {
        return self.getQuorumVerifier().getVotingMembers().containsKey(sid);
    }

    @Override
    public int getCurrentTick() {
        return self.tick.get();
    }

    @Override
    public int syncTimeout() {
        return self.tickTime * self.syncLimit;
    }

    @Override
    public int getTickOfNextAckDeadline() {
        return self.tick.get() + self.syncLimit;
    }

    @Override
    public int getTickOfInitialAckDeadline() {
        return self.tick.get() + self.initLimit + self.syncLimit;
    }

    @Override
    public long getAndDecrementFollowerCounter() {
        return followerCounter.getAndDecrement();
    }

    @Override
    public void touch(long sess, int to) {
        zk.touch(sess, to);
    }

    @Override
    public void submitLearnerRequest(Request si) {
        zk.submitLearnerRequest(si);
    }

    @Override
    public long getQuorumVerifierVersion() {
        return self.getQuorumVerifier().getVersion();
    }

    @Override
    public String getPeerInfo(long sid) {
        QuorumPeer.QuorumServer server = self.getView().get(sid);
        return server == null ? "" : server.toString();
    }

    @Override
    public byte[] getQuorumVerifierBytes() {
        return self.getLastSeenQuorumVerifier().toString().getBytes(UTF_8);
    }

    @Override
    public QuorumAuthServer getQuorumAuthServer() {
        return (self == null) ? null : self.authServer;
    }

    @Override
    public void revalidateSession(QuorumPacket qp, LearnerHandler learnerHandler) throws IOException {
        ByteArrayInputStream bis = new ByteArrayInputStream(qp.getData());
        DataInputStream dis = new DataInputStream(bis);
        long id = dis.readLong();
        int to = dis.readInt();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bos);
        dos.writeLong(id);
        boolean valid = zk.checkIfValidGlobalSession(id, to);
        if (valid) {
            try {
                // set the session owner as the follower that owns the session
                zk.setOwner(id, learnerHandler);
            } catch (KeeperException.SessionExpiredException e) {
                LOG.error(
                    "Somehow session 0x{} expired right after being renewed! (impossible)",
                    Long.toHexString(id),
                    e);
            }
        }
        if (LOG.isTraceEnabled()) {
            ZooTrace.logTraceMessage(
                LOG,
                ZooTrace.SESSION_TRACE_MASK,
                "Session 0x" + Long.toHexString(id) + " is valid: " + valid);
        }
        dos.writeBoolean(valid);
        qp.setData(bos.toByteArray());
        learnerHandler.queuePacket(qp);
    }

    @Override
    public void registerLearnerHandlerBean(final LearnerHandler learnerHandler, Socket socket) {
        LearnerHandlerBean bean = new LearnerHandlerBean(learnerHandler, socket);
        if (zk.registerJMX(bean)) {
            connectionBeans.put(learnerHandler, bean);
        }
    }

    @Override
    public void unregisterLearnerHandlerBean(final LearnerHandler learnerHandler) {
        LearnerHandlerBean bean = connectionBeans.remove(learnerHandler);
        if (bean != null) {
            MBeanRegistry.getInstance().unregister(bean);
        }
    }

}
