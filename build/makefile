PROJECT = "ELA Load Analyser"

WORK_DIR := $(shell pwd)
GO_WORK := $(WORK_DIR)/../
TARGET_DIR := $(GO_WORK)target
TARGET := ela

define rm_file
find "$(1)" -name "$(2)" -exec rm -- {} \$;
endef

define md5sums
$(shell cd $(1) && find ./ -type f \
		-not -path "./node_modules/*"\
		-not -path ".*/.umi/*"\
		-not -path ".*/.idea/*" \
		-not -path "./$(2)"\
		-exec md5sum {} \; | sort -k 2 | md5sum | awk '{print $$1}')
endef

define build_fronted
	echo "Build fronted"; \
	export MOCK=none; \
	cd $(1) && yarn; \
	cd $(1) && yarn build; \
	echo "Calculate files md5"; \
	echo $(call md5sums,$(1),$(2)) > "$(2)"
endef

bcc: OUT_SUFFIX := k
bcc: SRC_DIR := $(WORK_DIR)/../pkg/modules/module/src
bcc:
	@echo "Bcc source dir: $(SRC_DIR)";
	@echo "Clean old file"
	$(call rm_file,$(SRC_DIR),*.$(OUT_SUFFIX));

	@echo "Generate bcc code";
	@for line in $(wildcard $(SRC_DIR)/*.c) ; do \
	    grep -E '^#include[[:blank:]]+"[[:print:]]+"$$' "$${line}" | awk '{print $$2}' | tr -d '"' \
        | awk '{ if (NF > 0) {\
			if ($$1!="_dev.h") print $$1 \
		}}' | xargs -i cat $(SRC_DIR)/{} > "$${line}".$(OUT_SUFFIX); \
		echo "" >> "$${line}".$(OUT_SUFFIX); \
		sed '/^[[:blank:]]*#include[[:blank:]]\+"[[:print:]]\+"$$/d' "$${line}" | cat >> "$${line}".$(OUT_SUFFIX); \
		sed -i '/^[[:blank:]]*#include[[:blank:]]\+"_dev.h"$$/d' "$${line}".$(OUT_SUFFIX); \
	done

fronted: CHECKSUM := md5sums
fronted: FRONTED_DIR := $(WORK_DIR)/../pkg/web/template
fronted:
	@if [ "$(cache)" == "true" ] && [ -f "$(FRONTED_DIR)/$(CHECKSUM)" ] && [ -d "$(FRONTED_DIR)/dist" ] ; then \
		echo "Check MD5 sum"; \
		old_checksum=$(shell cat "$(FRONTED_DIR)/$(CHECKSUM)"); \
		new_checksum=$(call md5sums,$(FRONTED_DIR),$(CHECKSUM)); \
		echo "- old_checksum: $${old_checksum}"; \
		echo "- new_checksum: $${new_checksum}"; \
		if [ "$${old_checksum}" == "$${new_checksum}" ]; then \
			echo "files not change"; \
		else \
			$(call build_fronted,$(FRONTED_DIR),$(CHECKSUM)); \
		fi \
	else \
		$(call build_fronted,$(FRONTED_DIR),$(CHECKSUM)); \
	fi

go: BANNER_LEN_EXPR := github.com/xcphoenix/elf-load-analyser/pkg/env.BannerLen=
go: BANNER_PATH := $(WORK_DIR)/../pkg/env/banner.txt
go: bcc fronted
	@echo "Calculate banner width";
	banner_max_len=$(shell awk '{if (length(max)<length()) max=$$0}END{print length(max)+10;}' "$(BANNER_PATH)");
	ld_flags="$(shell echo " -X $(BANNER_LEN_EXPR)$${banner_max_len}")";

	mkdir -p "$(TARGET_DIR)"
	@echo "Start build target"
	@echo "Build with ld_flags: $${ld_flags}"

	if [ "$(release)" == "true" ]; then \
		echo "Release mode"; \
		cd $(GO_WORK) && go build -ldflags "$${ld_flags} -s -w" -o "$(TARGET_DIR)/$(TARGET)" \
                        github.com/xcphoenix/elf-load-analyser/cmd; \
	else \
		cd $(GO_WORK) && go build -ldflags "$${ld_flags}" -o "$(TARGET_DIR)/$(TARGET)" \
                github.com/xcphoenix/elf-load-analyser/cmd; \
	fi

compress: LEVEL ?= 9
compress: go
	@echo "Clean old binary";
	$(call rm_file,$(TARGET_DIR),$(TARGET)-compressed);

	@echo "Compressed";
	cd "$(TARGET_DIR)" && upx -$(LEVEL) -o $(TARGET)-compressed $(TARGET);

.PHONY: bcc,fronted,go,compress