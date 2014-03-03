ifndef PICOTCP
$(error Please point PICOTCP variable to your PICOTCP directory)
endif

PICOSTACK = $(PICOTCP)/stack
PICOINCLUDE= $(PICOTCP)/include 

$(PICOSTACK)/%.o: $(PICOINCLUDE)/%.h 
