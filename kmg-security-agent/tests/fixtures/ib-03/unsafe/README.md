# Transport boundary
The client connects through dispatch and tls_context. The backend is reachable only on loopback and is not a client listener. The documented deployment permits this private proxy-to-backend HTTP hop. The application returns account data after authentication. Certificate loading and listener wiring are deployment concerns outside this focused transport fixture.
