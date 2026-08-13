# BCLCA Related Package

This repository provides the implementation, formal verification, and
experimental evaluation materials associated with the paper:

**BCLCA: Blockchain-Assisted Certificateless Cross-Domain Authentication
Mechanism for LDACS**

The repository contains the following three components.

## 1. BCLCA implementation

This directory contains the implementation code related to the proposed
BCLCA scheme:

-   `blockchain_implementation/`: blockchain implementation for IPK
    credential management, including credential upload and query
    functions and the corresponding chaincode.
-   `cross_domain_auth/`: implementation of the proposed BCLCA
    cross-domain authentication and key agreement protocol.
-   `kgc_registration/`: implementation of the KGC-based entity
    registration procedure.

## 2. SPDL model

This directory contains:

-   `cross_domain_authentication.spdl`: the SPDL model used to Scyther verification.

The model corresponds to the formal verification presented in Section V
of the paper.

## 3. Test Result Plot

This directory contains the scripts and test values associated with 
the experimental resuts reported in Section VI
of the paper:

-   `communication_overhead.py`: communication overhead comparison.
-   `computational_overhead.py`: computational overhead comparison.
-   `latency_BCLCA.py`: authentication latency of BCLCA under different
    experimental settings.
-   `latency_compare.py`: authentication latency comparison with the
    reference schemes.


