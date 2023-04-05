ifdef FD_HAS_HOSTED
ifdef FD_HAS_OPENSSL
$(call make-unit-test,test_quic_hs,test_quic_hs,fd_aio fd_quic fd_util)
$(call make-unit-test,test_quic_streams,test_quic_streams,fd_aio fd_quic fd_util)
$(call make-unit-test,test_quic_conn,test_quic_conn,fd_aio fd_quic fd_util)
$(call make-unit-test,test_quic_server,test_quic_server,fd_aio fd_ballet fd_quic fd_tango fd_util)
$(call make-unit-test,test_quic_client_flood,test_quic_client_flood,fd_aio fd_ballet fd_quic fd_tango fd_util)
$(call make-unit-test,test_quic_bw,test_quic_bw,fd_aio fd_quic fd_util)
$(call make-unit-test,test_quic_handshake,test_handshake,fd_aio fd_quic fd_util)
$(call make-unit-test,test_quic_crypto,test_crypto,fd_quic fd_util)
$(call make-unit-test,test_quic_frames,test_frames,fd_quic fd_util)
$(call make-unit-test,test_quic_checksum,test_checksum,fd_util)
$(call make-unit-test,test_quic_tls_decrypt,test_tls_decrypt,fd_quic fd_util)
$(call make-bin,test_quic_layout,test_quic_layout,)
endif
endif
