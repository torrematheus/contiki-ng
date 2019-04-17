CONTIKI_PROJECT = coap-server
all: $(CONTIKI_PROJECT)

# Do not try to build on Sky because of code size limitation
PLATFORMS_EXCLUDE = sky z1

# Include the CoAP implementation
MODULES += os/net/app-layer/coap

MAKE_WITH_OSCORE = 1
CFLAGS += -DCONTEXT_NUM=1 -DTOKEN_SEQ_NUM=1 -DEP_CTX_NUM=1

# Include CoAP resources
MODULES_REL += ./resources

CONTIKI=../..
include $(CONTIKI)/Makefile.include
