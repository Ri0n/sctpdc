# sctpdc - SCTP + WebRTC DataChannel library

**The project is on design stage. Find the functional requirements below**

This Qt library combines simplified SCTP protocol implementation with WebRTC DataChannel protocol keeping aside all the other protocols and logic. The library is designed to be simple enough to add WebRTC DataChannel on top any existing DTLS or maybe other protocol.

**Features:**

* Operate with Qt native containers (QByteArray etc)
* Provide QIODevice-like object for every channel
* Provide real QIODevice-based object for reliable ordered channels
* Compatibility with latest versions of Google Chrome and Mozilla Firefox
* C++14
* Qt 5.6+

**In general it has next interface:**

* Write application data to the library to be DataChannel+SCTP encoded
* Write SCTP-encoded network data to the library to decode it
* Read decoded incoming data for an application
* Read encoded outgoing data for network
* Start handshake
* Signal when handshake is complete
* Signal proper session closing
* Signal errors
* Signal when decoded data is ready to be read by the application
* Signal when encoded data is ready to be written to the network
* Tune parameters like:
  * max payload size (MTU)
  * packets queue size (for stream reassembling)
  * retransmission timeout
  * packets ordering
  * reliability
  * number of channels
  * channel parameters like labels and others

**The work flow looks like following:**

1. Create data channel object
2. Setup parameters
3. Add channels (at least one is required)
3. Connect all signals and ensure incoming and outgoing data is properly handled
4. Start negotiation
5. Wait till successful handshake completion (signals will trigger `connected()`)
6. Do data transfer
7. Close the session
