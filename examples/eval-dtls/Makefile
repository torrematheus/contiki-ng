CONTIKI_PROJECT = coap-server
all: $(CONTIKI_PROJECT)

# Do not try to build on Sky because of code size limitation
PLATFORMS_EXCLUDE = sky z1

MAKE_WITH_DTLS=1
#MAKE_COAP_DTLS_KEYSTORE = MAKE_COAP_DTLS_KEYSTORE_SIMPLE
MAKE_COAP_DTLS_KEYSTORE = MAKE_COAP_DTLS_KEYSTORE_LWM2M
# Include the CoAP implementation
MODULES += os/net/app-layer/coap

# Include CoAP resources
MODULES_REL += ./resources

CONTIKI=../..
include $(CONTIKI)/Makefile.include
