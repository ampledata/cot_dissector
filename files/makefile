# pre-process protobuf files to replace "map" statements with equivalents

# XXX this shouldn't be necessary, but there's clearly a bug in the
#     dissector's map implementation, so until it's fixed...

# XXX edit this to be the location of the protobuf files
PROTODIR = $(HOME)/Documents/BBF/Standards/WT-369/wlupton/specification

# this should work with both python2 and python3
PREPROCESS = python protobuf-preprocess.py

PROTOFILES = $(notdir $(wildcard $(PROTODIR)/*.proto))

all: $(PROTOFILES)

%.proto: $(PROTODIR)/%.proto
	$(PREPROCESS) $< >$@

clean:
	$(RM) $(PROTOFILES)
