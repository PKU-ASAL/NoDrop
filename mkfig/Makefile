TARGET := draw
CPP_FILES := draw.cpp

PYCONF ?= python3-config
ifneq ($(shell $(PYCONF) > /dev/null 2>&1; echo $$?), 1)
$(error "no installation of PYTHON3 found")
endif

PYTHON_CFLAGS := $(shell $(PYCONF) --cflags)
PYTHON_LDFLAGS := $(shell $(PYCONF) --ldflags) -fPIC

all: $(TARGET)
$(TARGET): $(CPP_FILES)
	$(CXX) $^ -o $@ $(PYTHON_CFLAGS) $(PYTHON_LDFLAGS)

.PHONY: clean all
clean:
	rm -f $(TARGET)