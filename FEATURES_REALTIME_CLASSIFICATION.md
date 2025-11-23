# FEATURES_REALTIME_CLASSIFICATION.md

## Overview

This document classifies each feature into two categories: - **A: Strict
Real-Time (Streaming / packet-by-packet)** - **B: Zeek Real-Time (flow
ends allowed)**

A feature is considered extractable if the required information exists
in: - Raw packets (tcpdump) - Zeek logs (connection logs after flow
termination)

------------------------------------------------------------------------

# 1. FLOW-LEVEL FEATURES

  Feature                  Strict Real-Time (A)   Zeek Real-Time (B)   Notes
  ------------------------ ---------------------- -------------------- --------------------------------------
  flow_duration            ❌                     ✅                   Requires knowing flow end time.
  total_fwd_packets        ⚠️                     ✅                   Requires maintaining per-flow state.
  total_backward_packets   ⚠️                     ✅                   Same as above.
  total_packets            ⚠️                     ✅                   State-based.
  total_bytes              ⚠️                     ✅                   State-based.

------------------------------------------------------------------------

# 2. PACKET LENGTH FEATURES

  ---------------------------------------------------------------------------------------
  Feature                                   A          B          Notes
  ----------------------------------------- ---------- ---------- -----------------------
  fwd_packet_length_min/max/mean/std        ⚠️         ✅         Need full packet list.

  bwd_packet_length_min/max/mean/std        ⚠️         ✅         Same reason.

  packet_length_min/max/mean/std/variance   ⚠️         ✅         Full flow required.
  ---------------------------------------------------------------------------------------

------------------------------------------------------------------------

# 3. IAT (INTER ARRIVAL TIME) FEATURES

  Feature                     A    B    Notes
  --------------------------- ---- ---- --------------------
  fwd_iat_mean/std/min/max    ⚠️   ✅   Need whole flow.
  bwd_iat_mean/std/min/max    ⚠️   ✅   Whole flow needed.
  flow_iat_mean/std/min/max   ⚠️   ✅   Need all packets.

------------------------------------------------------------------------

# 4. FLAG FEATURES

  Feature            A    B    Notes
  ------------------ ---- ---- ---------------------------------------
  syn_flag_count     ⚠️   ✅   Depends on flow completion.
  fin_flag_count     ⚠️   ✅   FIN only occurs at end of connection.
  rst_flag_count     ⚠️   ✅   Same issue.
  total_flag_count   ⚠️   ✅   Needs all packets.

**Note:** In strict real-time streaming, only **instantaneous flag
values** are available, not counts.

------------------------------------------------------------------------

# 5. ACTIVE/IDLE FEATURES

  ------------------------------------------------------------------------
  Feature                       A         B         Notes
  ----------------------------- --------- --------- ----------------------
  active_mean/std/min/max       ❌        ❌        Cannot be computed
                                                    reliably.

  idle_mean/std/min/max         ❌        ❌        Requires knowing
                                                    overall flow
                                                    structure.
  ------------------------------------------------------------------------

------------------------------------------------------------------------

# 6. BULK FEATURES

  ------------------------------------------------------------------------
  Feature                       A         B         Notes
  ----------------------------- --------- --------- ----------------------
  fwd_avg\_\*\_bulk             ❌        ⚠️        Zeek does not compute
                                                    bulk metrics by
                                                    default.

  bwd_avg\_\*\_bulk             ❌        ⚠️        Same.
  ------------------------------------------------------------------------

------------------------------------------------------------------------

# 7. ADVANCED ENGINEERED FEATURES (PERSON 3)

  --------------------------------------------------------------------------
  Feature                       A         B         Notes
  ----------------------------- --------- --------- ------------------------
  flow_symmetry                 ⚠️        ✅        Requires
                                                    total_forward/backward
                                                    packets.

  byte_symmetry                 ⚠️        ✅        Needs full flow.

  burst_ratio                   ⚠️        ✅        Requires full IAT
                                                    sequence.

  packet_entropy                ⚠️        ⚠️        Can approximate online
                                                    but flow-end more
                                                    stable.

  syn_fin_ratio                 ❌        ✅        Requires total SYN & FIN
                                                    count.

  psh_ack_ratio                 ⚠️        ⚠️        Possible only with
                                                    flow-end.

  proto\_\*\_flag_rate          ⚠️        ⚠️        Partly real-time
                                                    possible.

  flow_anomaly_index            ❌        ⚠️        Depends on multiple
                                                    flow-completed features.

  skewness- and kurtosis-based  ❌        ⚠️        Need full sequence.
  features                                          
  --------------------------------------------------------------------------

------------------------------------------------------------------------

# 8. FEATURES SAFE TO REMOVE (NOT REAL-TIME EXTRACTABLE)

These features **cannot be extracted from tcpdump OR Zeek** reliably or
consistently:

-   active_mean, active_std, active_min, active_max\
-   idle_mean, idle_std, idle_min, idle_max\
-   fwd_avg_bytes/bulk\
-   fwd_avg_packets/bulk\
-   fwd_avg_bulk_rate\
-   bwd_avg_bytes/bulk\
-   bwd_avg_packets/bulk\
-   bwd_avg_bulk_rate\
-   flow_anomaly_index\
-   exp_packet_size\_\*\
-   exp_fwd_iat\_\*\
-   skew/kurtosis-based features (unless cached subset)

These can remain for modeling but are **not deployable in real-time**.

------------------------------------------------------------------------

# 9. FEATURES RECOMMENDED TO KEEP (REAL-TIME COMPATIBLE)

These are **real-time friendly** and recommended for production:

### Strong candidates:

-   total_fwd_packets
-   total_backward_packets
-   fwd_packet_length_mean
-   bwd_packet_length_mean
-   packet_rate
-   bytes_per_packet
-   syn_flag_count
-   ack_flag_count
-   psh_flag_count
-   rst_flag_count
-   total_flag_count
-   fwd_header_length
-   bwd_header_length
-   proto (0/6/17)
-   packet_entropy (approximation)
-   tcp_behavior
-   burst_ratio (approx)

------------------------------------------------------------------------

# 10. NEW RECOMMENDED ADVANCED FEATURES (PERSON 3)

These are **real-time compatible** and useful for attack detection:

### 1. **FWD/BWD Packet Burst Score**

`burst_score = (fwd_packets/s) / (bwd_packets/s + 1)`

### 2. **TCP Flag Transition Rate**

Counts how often flag changes occur:
`flag_change_rate = transitions / total_packets`

### 3. **Flow Direction Dominance**

`dir_dom = total_fwd_packets / (total_backward_packets + 1)`

### 4. **FWD/BWD IAT Burstiness**

`burst = iat_std / (iat_mean + eps)`

### 5. **Normalized Symmetry Index**

`(fwd - bwd) / (fwd + bwd + eps)`

------------------------------------------------------------------------

# FINAL NOTE

-   **Strict Real-Time (A) can use only per-packet instantaneous
    values.**
-   **Zeek (B) allows full flow analysis, so almost all flow-based
    features are safe.**

This document should guide which features to retain or drop for
deployment.
