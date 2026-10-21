TEMPLATE = lib
CONFIG -= qt
CONFIG += generateC

DISTFILES +=  $(HOME)/tool-inst/share/taste-types/taste-types.asn \
    samrh71.dv.xml \
    samv71.dv.xml
DISTFILES += taste-ccsds-sdls.msc
DISTFILES += interfaceview.xml
DISTFILES += work/binaries/*.msc
DISTFILES += work/binaries/coverage/index.html
DISTFILES += work/binaries/filters
DISTFILES += work/system.asn

DISTFILES += taste-ccsds-sdls.asn
DISTFILES += taste-ccsds-sdls.acn
include(work/taste.pro)
message($$DISTFILES)

