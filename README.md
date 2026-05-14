# LEO Satellite Intrusion Detection System using GDB-Augmented Deep Learning

## Overview

A hybrid Recurrent Neural Network IDS designed for the constraints of LEO satellite environments (modelled on SpaceX's Starlink), with the novelty of augmenting the input vector with low-level process state extracted via the GNU Project Debugger (GDB) at the point of packet processing.

The research question was whether feeding a neural classifier system-internal features (memory regions, local variables, function arguments) alongside conventional packet metrics could measurably reduce the high false-positive rate that traditional IDS struggle with. As far as I'm aware, this specific approach to deep packet analysis for neural classification hadn't been implemented before.

Two RNNs were trained and evaluated against each other: a baseline using only standard network features, and an augmented version with the additional GDB-derived features. Both used identical architectures so the input vector was the only variable.

## Results

| Metric | Baseline RNN | GDB-Augmented RNN |
| --- | --- | --- |
| Accuracy | 72% | 84% |
| Weighted F1 | 0.79 | 0.88 |
| Benign recall | 0.69 | 0.83 |
| Exploits precision | 0.14 | 0.72 |
| Exploits recall | 0.07 | 0.50 |
| Novel attack detection | 17/18 flagged | 17/18 flagged |

The increase in benign recall directly addresses the false-positive fallacy; the augmented model was substantially better at not mistaking benign traffic for attacks. The "Exploits" category of malicious traffic saw the largest gain, which makes intuitive sense: exploit attacks deliberately disturb system state, and that disturbance shows up clearly in lower-level features features.

Novel attack detection was unchanged. Augmentation didn't help the model identify attacks it had never seen before; it helped the model classify the attacks it had seen more accurately.

This was a controlled lab evaluation on a simulated environment using publicly available datasets. It is not a deployable system. See the limitations section.

## How it works

The pipeline has four stages:

**1. Dataset construction.** The LENS LEO satellite traffic dataset provides a baseline for satellite network characteristics (latency, jitter, packet loss). Attack signatures come from CIC-IDS2017 and UNSW-NB15. The Kitsune dataset was dropped during construction because its features are high-level abstractions that couldn't be reliably mapped back to individual packet flows. All non-satellite traffic metrics are ratio-normalised against the LENS baseline so the training data sits in a representative distribution for satellites.

**2. Simulated satellite environment (C).** A custom C server simulates a topology modelled on Starlink (since that's what the LENS LEO dataset is gathered from, i.e., user terminal -> satellite -> satellite -> ground station -> PoP) with realistic variable delays. Originally built in OMNeT++, then migrated to dockerised iPerf3/NetCat/Socat, then ultimately written from scratch in C; the earlier approaches all failed for GDB integration reasons (insufficient debugging symbols, scheduler interference with breakpoints, etc.). The custom server lives in a Docker container with capabilities stripped to a minimum and `ptrace_scope=1`, giving GDB a controlled, restricted launch environment.

**3. GDB augmentation.** GDB attaches to the C server and breakpoints fire inside the second satellite node's packet parser, immediately after acceptance and before routing. At each breakpoint, GDB dumps local variables, function arguments, and a 32-byte memory window around the packet buffer. These get appended to the packet data CSV files. The breakpoint placement is deliberately at routing rather than payload execution; placing it deeper would have given richer features but moves outside the satellite's IDS concern (an IDS should ideally detect malicious traffic before it actually executes).

**4. RNN classification.** A two-branch model: a static branch (dense layers) for high-level request metadata, and a sequential branch (stacked GRUs with attention) for the packet-by-packet sequence. Packet `Info` strings are tokenised with a custom regex tokeniser (which treats hex addresses as single tokens so that it can properly read GDB features) and embedded via FastText. Training uses focal loss and SMOTE to handle the heavy class imbalance, with a small number of underrepresented classes (Heartbleed, web attacks, worms, etc.) held out entirely from training to evaluate novel attack detection.

The model is intentionally lightweight because LEO satellites are computationally constrained; a heavy model is a non-starter for the actual operating environment, even if this code only ever ran on a workstation.

## Limitations and what I'd do differently

- Packet `Info` fields and GDB feature strings are tokenised, embedded, and then averaged. Averaging is computationally cheap but it almost certainly dilutes the temporal and structural information in the sequence. A more sophisticated aggregation; even a small transformer-style attention head over the tokens would probably retain more signal. I'd want to actually measure that tradeoff next time rather than just defaulting to averaging.
- The GDB breakpoint sits in the routing path, not the payload-handling path. This was a deliberate choice, but it means some of the features I extracted; processor register state, the backtrace, etc. were almost static across packets. With more time I'd experiment with multiple breakpoints at different stages of packet handling and only retain features that show meaningful variance.
- Even with focal loss, SMOTE, and weighted cross-entropy, the extreme underrepresentation of some attack classes meant they were effectively unlearnable. Domain-specific synthetic data generation, or pre-training on a more balanced dataset before fine tuning, would probably do better than SMOTE's interpolation approach.
- The original methodology included a Starlink-style 15-second IP reallocation scheduler. It worked, but its asynchronous handoffs were extremely difficult to handle with GDB halting the process at breakpoints, so the scheduler was removed. The LENS baseline data was already collected under a real scheduler so its effects are partly baked in, but a more thorough implementation would find a way to keep both.
- The C environment is a clean simulation, real LEO links have much more variation, weather effects, and electromagnetic interference that I didn't model. The results here should be read as a feasibility study for the augmentation approach, not as a performance measure for a deployed system.

## Tech stack

Python (TensorFlow, Keras, scikit-learn, imbalanced-learn, Scapy, gensim/FastText), C (libpcap), GDB, Docker, GNS3.

## Datasets

- **LENS** — LEO Network Measurement Dataset (Zhao & Pan, 2024)
- **CIC-IDS2017** — Canadian Institute for Cybersecurity
- **UNSW-NB15** — Australian Centre for Cyber Security

Full citations and licence acknowledgements are in the dissertation.

## Reading the full write-up

The dissertation PDF (`docs/dissertation.pdf`) contains the full background, methodology, implementation detail, and evaluation. The most relevant sections for understanding the contribution are §5.3 (GDB augmentation) and §6 (evaluation).

## Licence

Code released under the MIT Licence. See `LICENSE`. Datasets are subject to their original licences (linked in the dissertation references).
