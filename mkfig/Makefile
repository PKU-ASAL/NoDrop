TARGET := draw

VPATH := ../src

CPP_FILES := draw.cpp
C_FILES := events_table.c flags_table.c dynamic_params_table.c
CO_FILES := $(patsubst %.c,%.o,$(notdir ${C_FILES})) 
CPPO_FILES := $(patsubst %.cpp,%.o,$(notdir ${CPP_FILES}))
O_FILES := $(CO_FILES) $(CPPO_FILES)

PYCONF ?= /usr/bin/python3-config
ifneq ($(shell $(PYCONF) > /dev/null 2>&1; echo $$?), 1)
$(error "no installation of PYTHON3 found")
endif

PYTHON_CFLAGS := $(shell $(PYCONF) --cflags)
PYTHON_LDFLAGS := $(shell $(PYCONF) --ldflags)
INCLUDE_PATH := -I. -I../include
CFLAGS += -fPIC $(INCLUDE_PATH) $(PYTHON_CFLAGS)
CPPFLAGS += -fPIC -std=c++11 $(INCLUDE_PATH) $(PYTHON_CFLAGS)
LDFLAGS += -fpic $(PYTHON_LDFLAGS)

all: $(TARGET)
$(TARGET): $(O_FILES)
	$(CXX) $^ -o $@ $(LDFLAGS)

$(CO_FILES): %.o: %.c
	$(CC) $< -c $(CFLAGS) -o $@

$(CPPO_FILES): %.o: %.cpp
	$(CXX) $< -c $(CPPFLAGS) -o $@


.PHONY: clean all
clean:
	rm -f $(TARGET) $(O_FILES)