MGR = billmgr
PLUGIN = ntjabber

CFLAGS += -I/usr/local/mgr5/include/billmgr
CXXFLAGS += -I/usr/local/mgr5/include/billmgr

PKGNAMES = billmanager-plugin-ntjabber
RPM_PKGNAMES ?= $(PKGNAMES)
DEB_PKGNAMES ?= $(PKGNAMES)

WRAPPER += ntjabber
ntjabber_SOURCES = ntjabber.cpp
ntjabber_LDADD = -lbase -lnotifymodule
ntjabber_FOLDER = notify

WRAPPER += gwjabber
gwjabber_SOURCES = gwjabber.cpp
gwjabber_FOLDER = gate
gwjabber_LDADD = -lmgr -lmgrdb -lgloox
gwjabber_DLIBS = gatemodule

BASE ?= /usr/local/mgr5
include $(BASE)/src/isp.mk
