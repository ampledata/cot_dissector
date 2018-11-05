# pre-process protobuf files to remove maps
# XXX this shouldn't be necessary, but there's clearly a bug in the
#     dissector's map implementation, so until it's fixed...

# XXX edit this to be the location of the protobuf files
PROTODIR = $(HOME)/Documents/BBF/Standards/WT-369/wlupton/specification

# XXX edit this to be the location of the pre-processor tool
TOOL = $(HOME)/bin/protobuf-preprocess.py

PROTOFILES = $(notdir $(wildcard $(PROTODIR)/*.proto))

all: $(PROTOFILES)

%.proto: $(PROTODIR)/%.proto
	$(TOOL) $< >$@

clean:
	$(RM) $(PROTOFILES)
