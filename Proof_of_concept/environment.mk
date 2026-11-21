ifndef IXH_ENV_INCLUDED
IXH_ENV_INCLUDED := 1
VENV := $(APP)/.venv
ifeq ($(OS),Windows_NT)
PYTHON ?= python
ENV_PY := $(VENV)/Scripts/python.exe
else
PYTHON ?= python3
ENV_PY := $(VENV)/bin/python
endif

$(VENV)/pyvenv.cfg:
	"$(PYTHON)" -m venv "$(VENV)"

endif
