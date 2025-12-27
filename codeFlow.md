flowchart TD

%% =========================
%% PHASE 0: CRYPTOGEN
%% =========================
subgraph CG["cryptogen (offline phase)"]
    CG1["cmd/cryptogen/main.go<br/>main()"]
    CG2["generate()"]
    CG3["generatePeerOrg / generateOrdererOrg"]
    CG4["ca.NewCA(pqAlg?)<br/>PQ or ECDSA CA"]
    CG5["GenerateVerifyingMSP"]
    CG6["GenerateLocalMSP"]
    CG7["MSP folder on disk<br/>(cacerts, signcerts, keystore, ...)"]

    CG1 --> CG2 --> CG3
    CG3 --> CG4
    CG3 --> CG5
    CG3 --> CG6
    CG4 --> CG7
    CG5 --> CG7
    CG6 --> CG7
end

%% =========================
%% PHASE 1: PEER CLI ENTRY
%% =========================
subgraph CLI["peer CLI entrypoint"]
    P1["cmd/peer/main.go<br/>main()"]
    P2["cobra commands registration"]
    P3["peer node start"]

    P1 --> P2 --> P3
end

%% =========================
%% PHASE 2: INIT (CONFIG + CRYPTO)
%% =========================
subgraph INIT["InitCmd() – config & crypto bootstrap"]
    I1["internal/peer/common.InitCmd()"]
    I2["InitConfig(core.yaml)"]
    I3["InitCrypto()"]
    I4["InitBCCSPConfig()<br/>peer.BCCSP"]
    I5["factory.InitFactories()"]
    I6["GetLocalMspConfig()"]
    I7["mspmgmt.GetLocalMSP().Setup()"]

    I1 --> I2
    I2 --> I3
    I3 --> I4
    I4 --> I5
    I5 --> I6
    I6 --> I7
end

%% =========================
%% PHASE 3: MSP SETUP
%% =========================
subgraph MSP["MSP setup (bccspmsp)"]
    M1["bccspmsp.Setup()"]
    M2["setupSigningIdentity()"]
    M3["getSigningIdentityFromConf()"]

    M4["KeyImport(X509 cert)<br/>→ public key (SKI)"]
    M5["bccsp.GetKey(SKI)"]
    M6["KeyImport(PQ private key fallback)<br/>Falcon / Dilithium / ..."]
    M7["signer.New(bccsp, privKey)"]
    M8["msp.signer = SigningIdentity"]

    M1 --> M2 --> M3
    M3 --> M4 --> M5
    M5 -- found --> M7
    M5 -- not found --> M6 --> M7
    M7 --> M8
end

%% =========================
%% PHASE 4: PEER RUNTIME
%% =========================
subgraph RUN["peer runtime (serve)"]
    R1["internal/peer/node/start.go<br/>serve()"]
    R2["GetLocalMSP()"]
    R3["GetDefaultSigningIdentity()"]
    R4["init gossip"]
    R5["init ledger"]
    R6["init chaincode support"]
    R7["register Endorser / Deliver"]
    R8["peerServer.Start()"]

    R1 --> R2 --> R3
    R3 --> R4
    R3 --> R7
    R1 --> R5
    R1 --> R6
    R7 --> R8
end

%% =========================
%% CONNECTIONS
%% =========================
CG7 --> I6
P3 --> I1
I7 --> M1
M8 --> R3
