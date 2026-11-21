.DEFAULT_GOAL := help
APP := .
include environment.mk

.PHONY: help setup certify walkthrough demo archive-walkthrough audit verify recover compare test
help:
	@echo Paper protocol: setup, certify, audit, verify, walkthrough, test
	@echo Archive extension: demo, recover, compare, archive-walkthrough
	@echo Set RUN to a fresh output directory for generation.

RUN ?= run
SUITE ?= bls-pop
TRUST ?= $(RUN)/ledger-public.der
JPEG ?= $(RUN)/private/candidate.jpg
RECOVERED ?= $(RUN)/private/recovered.jpg

CLI := "$(ENV_PY)" -B "$(APP)/demo.py"
CHECKPOINT = "$(RUN)/certificate.json" --trust "$(TRUST)" --suite "$(SUITE)"
CERTIFY_CMD = $(CLI) certify "$(RUN)" --suite "$(SUITE)"
DEMO_CMD = $(CLI) demo "$(RUN)" --suite "$(SUITE)"
AUDIT_CMD = $(CLI) audit $(CHECKPOINT)
VERIFY_CMD = $(CLI) verify $(CHECKPOINT) "$(JPEG)" "$(RUN)/private/opening.bin" --evidence "$(RUN)/private/attestation.json"
RECOVER_CMD = $(CLI) recover $(CHECKPOINT) "$(RUN)/private/archive.json" "$(RUN)/private/reader-key.der" "$(RECOVERED)"
COMPARE_CMD = "$(ENV_PY)" -B -c "import filecmp, sys; sys.exit(0 if filecmp.cmp(sys.argv[1], sys.argv[2], shallow=False) else 'JPEG bytes differ')" "$(JPEG)" "$(RECOVERED)"

setup: $(VENV)/pyvenv.cfg
	"$(ENV_PY)" -m pip --disable-pip-version-check install -r "$(APP)/requirements.txt"

# Run the reader commands in separate processes and stop at the first failed check.
certify:
	$(CERTIFY_CMD)

walkthrough:
	$(CERTIFY_CMD)
	$(AUDIT_CMD)
	$(VERIFY_CMD)

archive-walkthrough:
	$(DEMO_CMD)
	$(AUDIT_CMD)
	$(VERIFY_CMD)
	$(RECOVER_CMD)
	$(COMPARE_CMD)
	@echo Recovered JPEG matches the candidate byte for byte.

demo:
	$(DEMO_CMD)

audit:
	$(AUDIT_CMD)

verify:
	$(VERIFY_CMD)

recover:
	$(RECOVER_CMD)

compare:
	$(COMPARE_CMD)
	@echo Recovered JPEG matches the candidate byte for byte.

test:
	"$(ENV_PY)" -B -m unittest discover -s "$(APP)" -p test_protocol.py -v

