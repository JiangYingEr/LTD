P4SRC_FILE = ltd.p4
P4C ?= p4c
P4_JSON = ltd.json
PYTHON ?= python3
SUDO ?= sudo
PCAP_DIR = pcap
LOG_DIR = log

all: run

# 参考 SecureINT 的用法：make 默认直接启动 Mininet 拓扑
run:
	$(SUDO) $(PYTHON) network_ltd.py --p4 $(P4SRC_FILE)

# 单独编译 P4，便于只做语法检查或生成 json
build:
	$(P4C) --target bmv2 --arch v1model $(P4SRC_FILE) -o $(P4_JSON)

# 单独启动拓扑，和 run 保持一致
topology:
	$(SUDO) $(PYTHON) network_ltd.py --p4 $(P4SRC_FILE)

# 启动 LTD 控制器
controller:
	$(PYTHON) controller.py

# 启动交换机 OS 逻辑
switch:
	$(SUDO) $(PYTHON) switch_os.py

# 清理 Mininet 残留
stop:
	$(SUDO) mn -c

clean: stop
	rm -f *.pcap *.json
	rm -rf $(PCAP_DIR) $(LOG_DIR)

.PHONY: all run build topology controller switch stop clean
