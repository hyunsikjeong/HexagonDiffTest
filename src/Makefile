# From Sim_API_Example
ARCH=67
Q6VERSION = v$(ARCH)

SDK_VERSION ?= 3.5.2
HEXAGON_TOOLS_VERSION ?= 8.3.07

SDK_ROOT ?= ${HOME}/Qualcomm
HEXAGON_SDK_ROOT ?= ${SDK_ROOT}/Hexagon_SDK/${SDK_VERSION}
HEXAGON_TOOLS_ROOT ?= ${HEXAGON_SDK_ROOT}/tools/HEXAGON_Tools/${HEXAGON_TOOLS_VERSION}

CC_HEXAGON := ${HEXAGON_TOOLS_ROOT}/Tools/bin/hexagon-clang
CXX_HEXAGON := ${HEXAGON_TOOLS_ROOT}/Tools/bin/hexagon-clang++
SIM_HEXAGON := ${HEXAGON_TOOLS_ROOT}/Tools/bin/hexagon-sim

SRC_TOP := $(shell pwd)
TARGET := template
MAIN := main
SRC_DIR := "$(SRC_TOP)/common"
BIN_DIR := "$(SRC_TOP)/common/out"

TARGET_C := $(SRC_DIR)/$(TARGET).c
TARGET_BIN = $(BIN_DIR)/$(TARGET).elf
MAIN_BIN := $(BIN_DIR)/$(MAIN).elf

CFLAGS = -m$(Q6VERSION) -g
SFLAGS = --m$(Q6VERSION) --pmu_statsfile /dev/null --statsfile /dev/null


all: clean build

clean:
	rm -rf $(BIN_DIR) pmu_statsfile.txt stats.txt

build:
	mkdir -p $(BIN_DIR)
	$(CC_HEXAGON) $(CFLAGS) -o $(TARGET_BIN) $(TARGET_C)
	cp $(TARGET_BIN) $(MAIN_BIN)

sim:
	$(SIM_HEXAGON) $(SFLAGS) $(MAIN_BIN)


